use super::traits::{BitwiseOperationGadget, IsWitness};
use anyhow::anyhow;
use ark_ff::Field;
use ark_r1cs_std::prelude::Boolean;

impl<F: Field> IsWitness<F> for Boolean<F> {
    fn is_witness(&self) -> anyhow::Result<bool>
    where
        Self: ark_r1cs_std::ToBytesGadget<F>,
    {
        if let ark_r1cs_std::prelude::Boolean::Is(bool)
        | ark_r1cs_std::prelude::Boolean::Not(bool) = self
        {
            Ok(bool.variable().is_witness())
        } else {
            Ok(false)
        }
    }
}

impl<F: Field> BitwiseOperationGadget<F> for Boolean<F> {
    fn and(&self, other_gadget: &Self) -> anyhow::Result<Self>
    where
        Self: std::marker::Sized,
    {
        self.and(other_gadget).map_err(|e| anyhow!(e))
    }

    fn nand(&self, other_gadget: &Self) -> anyhow::Result<Self>
    where
        Self: std::marker::Sized,
    {
        Boolean::kary_nand(&[self.clone(), other_gadget.clone()]).map_err(|e| anyhow!(e))
    }

    fn nor(&self, other_gadget: &Self) -> anyhow::Result<Self>
    where
        Self: std::marker::Sized,
    {
        Ok(self.or(other_gadget)?.not())
    }

    fn or(&self, other_gadget: &Self) -> anyhow::Result<Self>
    where
        Self: std::marker::Sized,
    {
        self.or(other_gadget).map_err(|e| anyhow!(e))
    }

    fn xor(&self, other_gadget: &Self) -> anyhow::Result<Self>
    where
        Self: std::marker::Sized,
    {
        self.xor(other_gadget).map_err(|e| anyhow!(e))
    }
}
