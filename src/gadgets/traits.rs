use anyhow::{anyhow, Result};
use ark_ff::Field;
use ark_r1cs_std::{ToBitsGadget, ToBytesGadget};

pub trait ToFieldElements<F: Field> {
    fn to_field_elements(&self) -> Result<Vec<F>>;
}

pub trait IsWitness<F: Field> {
    fn is_witness(&self) -> Result<bool>
    where
        Self: ToBytesGadget<F>,
    {
        let bytes = self.to_bytes().map_err(|e| anyhow!("{}", e))?;

        let byte = bytes
            .first()
            .ok_or("Error getting first UInt8 byte")
            .map_err(|e| anyhow!("{}", e))?;

        let bits = byte.to_bits_be().map_err(|e| anyhow!("{}", e))?;

        let bit = bits
            .first()
            .ok_or("Error getting the first Boolean bit")
            .map_err(|e| anyhow!("{}", e))?;

        if let ark_r1cs_std::prelude::Boolean::Is(bool)
        | ark_r1cs_std::prelude::Boolean::Not(bool) = bit
        {
            Ok(bool.variable().is_witness())
        } else {
            Ok(false)
        }
    }
}
