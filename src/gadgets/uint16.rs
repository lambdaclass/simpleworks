use super::helpers;
use super::traits::{
    ArithmeticGadget, BitManipulationGadget, BitwiseOperationGadget, ComparisonGadget,
    FromBytesGadget, IsWitness, ToFieldElements,
};
use super::Comparison;
use anyhow::{ensure, Result};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    prelude::{AllocVar, Boolean},
    uint16::UInt16,
    uint8::UInt8,
    R1CSVar, ToBitsGadget,
};
use ark_relations::{
    lc,
    r1cs::{ConstraintSystemRef, SynthesisError},
};

use ark_r1cs_std::select::CondSelectGadget;

impl<F: Field> ToFieldElements<F> for UInt16<F> {
    fn to_field_elements(&self) -> Result<Vec<F>> {
        let bits_le = self.to_bits_le();
        let mut result = Vec::with_capacity(16);
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

impl<F: Field> FromBytesGadget<F> for UInt16<F> {
    fn from_bytes_le(bytes: &[UInt8<F>]) -> Result<Self>
    where
        Self: Sized,
    {
        let mut bytes_as_booleans: Vec<Vec<Boolean<F>>> = Vec::new();
        bytes.iter().try_for_each(|elem| {
            let bits = elem.to_bits_le()?;
            bytes_as_booleans.push(bits);
            Ok::<_, anyhow::Error>(())
        })?;

        let bits: Vec<Boolean<F>> = bytes_as_booleans.into_iter().flatten().collect();

        Ok(Self::from_bits_le(&bits))
    }

    fn from_bytes_be(bytes: &[UInt8<F>]) -> Result<Self>
    where
        Self: Sized,
    {
        let mut reversed_bytes = bytes.to_vec();
        reversed_bytes.reverse();
        Self::from_bytes_le(&reversed_bytes)
    }
}

impl<F: Field> IsWitness<F> for UInt16<F> {}

impl<F: Field> BitwiseOperationGadget<F> for UInt16<F> {
    fn and(&self, other_gadget: &Self) -> Result<Self>
    where
        Self: std::marker::Sized,
    {
        let result = helpers::zip_bits_and_apply(
            self.to_bits_le(),
            other_gadget.to_bits_le(),
            |first_bit, second_bit| first_bit.and(&second_bit),
        )?;
        let new_value = UInt16::from_bits_le(&result);
        Ok(new_value)
    }

    fn nand(&self, other_gadget: &Self) -> Result<Self>
    where
        Self: std::marker::Sized,
    {
        let result = helpers::zip_bits_and_apply(
            self.to_bits_le(),
            other_gadget.to_bits_le(),
            |first_bit, second_bit| Ok(first_bit.and(&second_bit)?.not()),
        )?;
        let new_value = UInt16::from_bits_le(&result);
        Ok(new_value)
    }

    fn nor(&self, other_gadget: &Self) -> Result<Self>
    where
        Self: std::marker::Sized,
    {
        let result = helpers::zip_bits_and_apply(
            self.to_bits_le(),
            other_gadget.to_bits_le(),
            |first_bit, second_bit| Ok(first_bit.or(&second_bit)?.not()),
        )?;
        let new_value = UInt16::from_bits_le(&result);
        Ok(new_value)
    }

    fn or(&self, other_gadget: &Self) -> Result<Self>
    where
        Self: std::marker::Sized,
    {
        let result = helpers::zip_bits_and_apply(
            self.to_bits_le(),
            other_gadget.to_bits_le(),
            |first_bit, second_bit| first_bit.or(&second_bit),
        )?;
        let new_value = UInt16::from_bits_le(&result);
        Ok(new_value)
    }

    fn xor(&self, other_gadget: &Self) -> Result<Self>
    where
        Self: std::marker::Sized,
    {
        let result = helpers::zip_bits_and_apply(
            self.to_bits_le(),
            other_gadget.to_bits_le(),
            |first_bit, second_bit| first_bit.xor(&second_bit),
        )?;
        let new_value = UInt16::from_bits_le(&result);
        Ok(new_value)
    }
}

impl<F: Field> BitManipulationGadget<F> for UInt16<F> {
    fn rotate_left(
        &self,
        positions: usize,
        constraint_system: ConstraintSystemRef<F>,
    ) -> Result<Self> {
        let mut primitive_bits = self.to_bits_le();
        primitive_bits.reverse();
        let mut rotated_bits = primitive_bits.clone();
        rotated_bits.rotate_left(positions);

        for i in 0..16 {
            if let (Some(a), Some(b)) = (
                &primitive_bits.get((i + positions) % 16),
                &rotated_bits.get(i),
            ) {
                let c = lc!() + a.lc() - b.lc();
                constraint_system.enforce_constraint(lc!(), lc!(), c)?
            }
        }

        rotated_bits.reverse();
        Ok(UInt16::<F>::from_bits_le(&rotated_bits))
    }

    fn rotate_right(
        &self,
        positions: usize,
        constraint_system: ConstraintSystemRef<F>,
    ) -> Result<Self> {
        // Example: rotate one place to the right is the same as rotate 7 places
        // to the left while generating the same number of constraints.
        // We compute positions % 16 to avoid subtraction overflow when someone
        // tries to rotate more then 16 positions.
        self.rotate_left(16 - (positions % 16), constraint_system)
    }
    fn shift_left(
        &self,
        positions: usize,
        constraint_system: ConstraintSystemRef<F>,
    ) -> Result<Self>
    where
        Self: std::marker::Sized,
    {
        let mut primitive_bits = self.to_bits_le();
        primitive_bits.reverse();
        let shifted_value = UInt16::<F>::new_witness(constraint_system.clone(), || {
            let position_as_u32: u32 = positions
                .try_into()
                .map_err(|_e| SynthesisError::Unsatisfiable)?;
            let (shifted_value, shift_overflowed) = self.value()?.overflowing_shl(position_as_u32);
            if shift_overflowed {
                Ok(0)
            } else {
                Ok(shifted_value)
            }
        })?;
        let mut shifted_bits = shifted_value.to_bits_le();
        shifted_bits.reverse();

        if positions >= 16 {
            for c in shifted_bits.iter() {
                constraint_system.enforce_constraint(lc!(), lc!(), c.lc())?;
            }
        } else {
            // Check that the last positions bits are 0s.
            shifted_bits
                .iter()
                .skip(16 - (positions % 16))
                .try_for_each(|c| {
                    constraint_system.enforce_constraint(lc!(), lc!(), c.lc())?;
                    Ok::<_, anyhow::Error>(())
                })?;
            // Check that the first positions bits are the last positions bits of the primitive bits.
            shifted_bits
                .iter()
                .take(positions)
                .zip(primitive_bits.iter().skip(positions))
                .try_for_each(|(b, a)| {
                    let c = lc!() + a.lc() - b.lc();
                    constraint_system.enforce_constraint(lc!(), lc!(), c)?;
                    Ok::<_, anyhow::Error>(())
                })?;
        }

        Ok(shifted_value)
    }

    fn shift_right(
        &self,
        positions: usize,
        constraint_system: ConstraintSystemRef<F>,
    ) -> Result<Self>
    where
        Self: std::marker::Sized,
    {
        let mut primitive_bits = self.to_bits_le();
        primitive_bits.reverse();
        let shifted_value = UInt16::<F>::new_witness(constraint_system.clone(), || {
            let position_as_u32: u32 = positions
                .try_into()
                .map_err(|_e| SynthesisError::Unsatisfiable)?;
            let (shifted_value, shift_overflowed) = self.value()?.overflowing_shr(position_as_u32);
            if shift_overflowed {
                Ok(0)
            } else {
                Ok(shifted_value)
            }
        })?;
        let mut shifted_bits = shifted_value.to_bits_le();
        shifted_bits.reverse();

        if positions >= 16 {
            for c in shifted_bits.iter() {
                constraint_system.enforce_constraint(lc!(), lc!(), c.lc())?;
            }
        } else {
            // Check that the first positions primitive bits are 0s.
            shifted_bits.iter().take(positions).try_for_each(|c| {
                constraint_system.enforce_constraint(lc!(), lc!(), c.lc())?;
                Ok::<_, anyhow::Error>(())
            })?;
            // Check that the last len - positions bits are the first positions bits of the primitive bits.
            shifted_bits
                .iter()
                .skip(positions)
                .zip(primitive_bits.iter().take(positions))
                .try_for_each(|(b, a)| {
                    let c = lc!() + a.lc() - b.lc();
                    constraint_system.enforce_constraint(lc!(), lc!(), c)?;
                    Ok::<_, anyhow::Error>(())
                })?;
        }

        Ok(shifted_value)
    }
}

impl<F: Field + PrimeField> ArithmeticGadget<F> for UInt16<F> {
    fn add(&self, addend: &Self) -> Result<Self>
    where
        Self: std::marker::Sized,
    {
        let result = Self::addmany(&[self.clone(), addend.clone()])?;
        Ok(result)
    }

    fn sub(&self, subtrahend: &Self) -> Result<Self>
    where
        Self: std::marker::Sized,
    {
        ensure!(
            self.value()? >= subtrahend.value()?,
            "Subtraction underflow"
        );

        let minuend_as_augend = Self::from_bits_le(
            &(self
                .to_bits_le()
                .into_iter()
                .map(|bit| bit.not())
                .collect::<Vec<Boolean<F>>>()),
        );
        let subtrahend_as_addend = subtrahend.to_bits_le();

        let subtrahend_as_addend_var = Self::from_bits_le(&subtrahend_as_addend);

        let partial_result = Self::addmany(&[minuend_as_augend, subtrahend_as_addend_var])?;

        let difference = Self::from_bits_le(
            &partial_result
                .to_bits_le()
                .into_iter()
                .map(|bit| bit.not())
                .collect::<Vec<Boolean<F>>>(),
        );

        Ok(difference)
    }

    fn div(&self, divisor: &Self, constraint_system: ConstraintSystemRef<F>) -> Result<Self>
    where
        Self: std::marker::Sized,
    {
        ensure!(divisor.value()? != 0_u16, "attempt to divide by zero");
        let mut quotient = self.clone();
        let mut aux = Self::new_witness(constraint_system.clone(), || Ok(0))?;

        let one = Self::new_constant(constraint_system.clone(), 1)?;

        for dividend_bit in self.to_bits_le().iter().rev() {
            quotient = quotient.shift_left(1, constraint_system.clone())?;
            aux = Self::conditionally_select(
                dividend_bit,
                &aux.shift_left(1, constraint_system.clone())?.or(&one)?,
                &aux.shift_left(1, constraint_system.clone())?,
            )?;

            let is_greater =
                divisor.compare(&aux, Comparison::GreaterThan, constraint_system.clone())?;

            quotient = Self::conditionally_select(&is_greater, &quotient, &quotient.or(&one)?)?;
            aux = if is_greater.value()? {
                aux
            } else {
                aux.sub(divisor)?
            }
        }
        Ok(quotient)
    }

    fn mul(&self, multiplicand: &Self, constraint_system: ConstraintSystemRef<F>) -> Result<Self>
    where
        Self: std::marker::Sized,
    {
        let mut product = Self::new_witness(constraint_system.clone(), || Ok(0))?;
        for (i, multiplier_bit) in self.to_bits_le().iter().enumerate() {
            // If the multiplier bit is a 1.
            let addend = multiplicand.shift_left(i, constraint_system.clone())?;
            product = Self::conditionally_select(
                multiplier_bit,
                &Self::addmany(&[product.clone(), addend])?,
                &product,
            )?;
        }
        Ok(product)
    }
}

impl<F: Field> ComparisonGadget<F> for UInt16<F> {
    fn compare(
        &self,
        gadget_to_compare: &Self,
        comparison: Comparison,
        constraint_system: ConstraintSystemRef<F>,
    ) -> Result<Boolean<F>>
    where
        Self: std::marker::Sized,
    {
        helpers::compare_ord(self, gadget_to_compare, comparison, constraint_system)
    }
}

#[cfg(test)]
mod tests {
    use crate::gadgets::{traits::BitManipulationGadget, ConstraintF, UInt16Gadget};
    use ark_r1cs_std::{prelude::AllocVar, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_one_left_rotation() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let byte = UInt16Gadget::new_witness(cs.clone(), || Ok(0xF000)).unwrap();
        let positions_to_rotate = 1;
        let expected_byte = byte.value().unwrap().rotate_left(positions_to_rotate);

        let result = byte
            .rotate_left(positions_to_rotate.try_into().unwrap(), cs.clone())
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(expected_byte, result.value().unwrap());
        assert_eq!(result.value().unwrap(), 0xE001);
    }

    #[test]
    fn test_more_than_one_left_rotation() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let byte = UInt16Gadget::new_witness(cs.clone(), || Ok(0xF000)).unwrap();
        let positions_to_rotate = 2;
        let expected_byte = byte.value().unwrap().rotate_left(positions_to_rotate);

        let result = byte
            .rotate_left(positions_to_rotate.try_into().unwrap(), cs.clone())
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(expected_byte, result.value().unwrap());
        assert_eq!(result.value().unwrap(), 0xC003);
    }

    #[test]
    fn test_one_right_rotation() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let byte = UInt16Gadget::new_witness(cs.clone(), || Ok(0xC003)).unwrap();
        let positions_to_rotate = 1;
        let expected_byte = byte.value().unwrap().rotate_right(positions_to_rotate);

        let result = byte
            .rotate_right(positions_to_rotate.try_into().unwrap(), cs.clone())
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(expected_byte, result.value().unwrap());
        assert_eq!(result.value().unwrap(), 0xE001);
    }

    #[test]
    fn test_more_than_one_right_rotation() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let byte = UInt16Gadget::new_witness(cs.clone(), || Ok(0xC003)).unwrap();
        let positions_to_rotate = 2;
        let expected_byte = byte.value().unwrap().rotate_right(positions_to_rotate);

        let result = byte
            .rotate_right(positions_to_rotate.try_into().unwrap(), cs.clone())
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(expected_byte, result.value().unwrap());
        assert_eq!(result.value().unwrap(), 0xF000);
    }

    #[test]
    fn test_one_left_shift() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let byte = UInt16Gadget::new_witness(cs.clone(), || Ok(1)).unwrap();
        let positions_to_shift = 1_i32;
        let expected_byte = byte.value().unwrap() << positions_to_shift;

        let result = byte
            .shift_left(positions_to_shift.try_into().unwrap(), cs.clone())
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(expected_byte, result.value().unwrap());
    }

    #[test]
    fn test_more_than_one_left_shift() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let byte = UInt16Gadget::new_witness(cs.clone(), || Ok(1)).unwrap();
        let positions_to_shift = 2_i32;
        let expected_byte = byte.value().unwrap() << positions_to_shift;

        let result = byte
            .shift_left(positions_to_shift.try_into().unwrap(), cs.clone())
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(expected_byte, result.value().unwrap());
    }

    #[test]
    fn test_overflow_one_bit_left_shift() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let byte = UInt16Gadget::new_witness(cs.clone(), || Ok(0b1000_0000_0000_0001)).unwrap();
        let positions_to_shift = 1_i32;
        let expected_byte = UInt16Gadget::constant(2).value().unwrap();

        let result = byte
            .shift_left(positions_to_shift.try_into().unwrap(), cs.clone())
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(expected_byte, result.value().unwrap());
    }

    #[test]
    fn test_overflow_all_bits_left_shift() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let byte = UInt16Gadget::new_witness(cs.clone(), || Ok(1)).unwrap();
        let positions_to_shift = 16_i32;
        let expected_byte = 0_u16;

        let result = byte
            .shift_left(positions_to_shift.try_into().unwrap(), cs.clone())
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(expected_byte, result.value().unwrap());
        assert_eq!(0, result.value().unwrap());
    }

    #[test]
    fn test_one_right_shift() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let byte = UInt16Gadget::new_witness(cs.clone(), || Ok(2)).unwrap();
        let positions_to_shift = 1_i32;
        let expected_byte = byte.value().unwrap() >> positions_to_shift;

        let result = byte
            .shift_right(positions_to_shift.try_into().unwrap(), cs.clone())
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(expected_byte, result.value().unwrap());
    }

    #[test]
    fn test_more_than_one_right_shift() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let byte = UInt16Gadget::new_witness(cs.clone(), || Ok(4)).unwrap();
        let positions_to_shift = 2_i32;
        let expected_byte = byte.value().unwrap() >> positions_to_shift;

        let result = byte
            .shift_right(positions_to_shift.try_into().unwrap(), cs.clone())
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(expected_byte, result.value().unwrap());
    }

    #[test]
    fn test_overflow_one_bit_right_shift() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let byte = UInt16Gadget::new_witness(cs.clone(), || Ok(1)).unwrap();
        let positions_to_shift = 1_i32;
        let expected_byte = UInt16Gadget::constant(0).value().unwrap();

        let result = byte
            .shift_right(positions_to_shift.try_into().unwrap(), cs.clone())
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(expected_byte, result.value().unwrap());
    }

    #[test]
    fn test_overflow_all_bits_right_shift() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let byte = UInt16Gadget::new_witness(cs.clone(), || Ok(u16::MAX)).unwrap();
        let positions_to_shift = 16_i32;
        let expected_byte = 0_u16;

        let result = byte
            .shift_right(positions_to_shift.try_into().unwrap(), cs.clone())
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(expected_byte, result.value().unwrap());
    }
}
