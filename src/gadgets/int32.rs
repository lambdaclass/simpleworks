use ark_ff::{Field, One, PrimeField, Zero};
use ark_r1cs_std::{
    boolean::AllocatedBool,
    prelude::{AllocVar, AllocationMode, Boolean, EqGadget},
    Assignment, R1CSVar, ToBitsGadget,
};
use ark_relations::{
    lc,
    r1cs::{ConstraintSystemRef, LinearCombination, Namespace, SynthesisError, Variable},
};
use num_bigint::BigInt;
use num_traits::cast::ToPrimitive;
use std::borrow::Borrow;

const I32_SIZE_IN_BITS: usize = 32;
const OPERANDS_LEN: usize = 2;

/// Represents an interpretation of 8 `Boolean` objects as an
/// unsigned integer.
#[derive(Clone, Debug)]
pub struct Int32<F: Field> {
    /// Little-endian representation: least significant bit first
    pub(crate) bits: [Boolean<F>; I32_SIZE_IN_BITS],
    pub(crate) value: Option<i32>,
}

impl<F: Field> Int32<F> {
    /// Construct a constant `Int32` from a `i32`
    ///
    /// This *does not* create new variables or constraints.
    ///
    /// ```
    /// # fn main() -> Result<(), ark_relations::r1cs::SynthesisError> {
    /// // We'll use the BLS12-381 scalar field for our constraints.
    /// use ark_test_curves::bls12_381::Fr;
    /// use ark_relations::r1cs::*;
    /// use ark_r1cs_std::prelude::*;
    ///
    /// let cs = ConstraintSystem::<Fr>::new_ref();
    /// let var = Int32::new_witness(cs.clone(), || Ok(2))?;
    ///
    /// let constant = Int32::constant(2);
    /// var.enforce_equal(&constant)?;
    /// assert!(cs.is_satisfied().unwrap());
    /// # Ok(())
    /// # }
    /// ```
    pub fn constant(value: i32) -> Self {
        let mut bits = [Boolean::FALSE; I32_SIZE_IN_BITS];

        let mut tmp = value;

        bits.iter_mut().for_each(|bit| {
            // If last bit is one, push one.
            *bit = Boolean::constant((tmp & 1) == 1);
            tmp >>= 1;
        });

        Self {
            bits,
            value: Some(value),
        }
    }

    /// Perform modular addition of `operands`.
    ///
    /// The user must ensure that overflow does not occur.
    pub fn addmany(operands: &[Self]) -> Result<Self, SynthesisError>
    where
        F: PrimeField,
    {
        // Compute the maximum value of the sum so we allocate enough bits for
        // the result
        let mut max_value = BigInt::from(i32::max_value()) * BigInt::from(OPERANDS_LEN);

        // Keep track of the resulting value
        let mut result_value = Some(BigInt::zero());

        // This is a linear combination that we will enforce to be "zero"
        let mut lc = LinearCombination::zero();

        let mut all_constants = true;

        // Iterate over the operands
        for op in operands {
            // Accumulate the value
            match op.value {
                Some(val) => {
                    if let Some(v) = result_value.as_mut() {
                        *v += BigInt::from(val)
                    }
                }

                None => {
                    // If any of our operands have unknown value, we won't
                    // know the value of the result
                    result_value = None;
                }
            }

            // Iterate over each bit_gadget of the operand and add the operand to
            // the linear combination
            let mut coeff = F::one();
            for bit in &op.bits {
                match *bit {
                    Boolean::Is(ref bit) => {
                        all_constants = false;

                        // Add coeff * bit_gadget
                        lc += (coeff, bit.variable());
                    }
                    Boolean::Not(ref bit) => {
                        all_constants = false;

                        // Add coeff * (1 - bit_gadget) = coeff * ONE - coeff * bit_gadget
                        lc = lc + (coeff, Variable::One) - (coeff, bit.variable());
                    }
                    Boolean::Constant(bit) => {
                        if bit {
                            lc += (coeff, Variable::One);
                        }
                    }
                }

                coeff.double_in_place();
            }
        }

        // The value of the actual result is modulo 2^$size
        let modular_value = result_value.clone().map(|v| {
            let modulus = BigInt::from(1_u64)
                << (I32_SIZE_IN_BITS
                    .to_u32()
                    .ok_or("I32_SIZE_IN_BITS value cannot be represented as u32.")?);
            (v % modulus)
                .to_i32()
                .ok_or("Modular value cannot be represented as i32.")
        });

        if let Some(Ok(modular_value)) = modular_value {
            if all_constants {
                return Ok(Self::constant(modular_value));
            }
        }
        let cs = operands.cs();

        // Storage area for the resulting bits
        let mut result_bits = vec![];

        // Allocate each bit_gadget of the result
        let mut coeff = F::one();
        let mut i = 0;
        while max_value != BigInt::zero() {
            // Allocate the bit_gadget
            let b = AllocatedBool::new_witness(cs.clone(), || {
                result_value
                    .clone()
                    .map(|v| (v >> i) & BigInt::one() == BigInt::one())
                    .get()
            })?;

            // Subtract this bit_gadget from the linear combination to ensure the sums
            // balance out
            lc = lc - (coeff, b.variable());

            result_bits.push(b.into());

            max_value >>= 1;
            i += 1;
            coeff.double_in_place();
        }

        // Enforce that the linear combination equals zero
        cs.enforce_constraint(lc!(), lc!(), lc)?;

        // Discard carry bits that we don't care about
        result_bits.truncate(I32_SIZE_IN_BITS);
        let bits = match TryFrom::try_from(result_bits) {
            Ok(bits) => bits,
            Err(_e) => todo!(),
        };

        match modular_value {
            Some(Ok(modular_value)) => Ok(Self {
                bits,
                value: Some(modular_value),
            }),
            Some(Err(_e)) => todo!(),
            None => todo!(),
        }
    }
}

impl<ConstraintF: Field> AllocVar<i32, ConstraintF> for Int32<ConstraintF> {
    fn new_variable<T: Borrow<i32>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let value = f().map(|f| *f.borrow()).ok();

        let mut values = [None; 32];
        if let Some(val) = value {
            values
                .iter_mut()
                .enumerate()
                .for_each(|(i, v)| *v = Some((val >> i) & 1 == 1));
        }

        let mut bits = [Boolean::FALSE; 32];
        for (b, v) in bits.iter_mut().zip(&values) {
            *b = Boolean::new_variable(cs.clone(), || v.get(), mode)?;
        }
        Ok(Self { bits, value })
    }
}

impl<ConstraintF: Field> EqGadget<ConstraintF> for Int32<ConstraintF> {
    fn is_eq(&self, other: &Self) -> Result<Boolean<ConstraintF>, SynthesisError> {
        self.bits.as_ref().is_eq(&other.bits)
    }

    fn conditional_enforce_equal(
        &self,
        other: &Self,
        condition: &Boolean<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        self.bits.conditional_enforce_equal(&other.bits, condition)
    }

    fn conditional_enforce_not_equal(
        &self,
        other: &Self,
        condition: &Boolean<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        self.bits
            .conditional_enforce_not_equal(&other.bits, condition)
    }
}

impl<F: Field> ToBitsGadget<F> for Int32<F> {
    fn to_bits_le(&self) -> Result<Vec<Boolean<F>>, SynthesisError> {
        Ok(self.bits.to_vec())
    }
}

impl<F: Field> R1CSVar<F> for Int32<F> {
    type Value = i32;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.bits.as_ref().cs()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        let mut value = None;
        for (i, bit) in self.bits.iter().enumerate() {
            let b = i32::from(bit.value()?);
            value = match value {
                Some(value) => Some(value + (b << i)),
                None => Some(b << i),
            };
        }
        debug_assert_eq!(self.value, value);
        value.get()
    }
}

#[cfg(test)]
mod tests {
    use super::Int32;
    use ark_bls12_381::Fr;
    use ark_r1cs_std::{prelude::AllocVar, R1CSVar, ToBitsGadget};
    use ark_relations::r1cs::{ConstraintSystem, SynthesisError};

    #[test]
    fn test_int8_from_bits_to_bits() -> Result<(), SynthesisError> {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let byte_val = 0b0111_0001;
        let byte =
            Int32::new_witness(ark_relations::ns!(cs, "alloc value"), || Ok(byte_val)).unwrap();
        let bits = byte.to_bits_le()?;

        for (i, bit) in bits.iter().enumerate() {
            assert_eq!(bit.value()?, (byte_val >> i) & 1 == 1)
        }
        Ok(())
    }
}
