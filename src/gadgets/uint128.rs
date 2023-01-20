use super::helpers::zip_bits_and_apply;
use super::traits::{BitwiseOperationGadget, FromBytesGadget, IsWitness, ToFieldElements};
use anyhow::Result;
use ark_ff::Field;
use ark_r1cs_std::{
    prelude::{AllocVar, Boolean},
    uint128::UInt128,
    uint8::UInt8,
    R1CSVar, ToBitsGadget,
};
use ark_relations::{
    lc,
    r1cs::{ConstraintSystemRef, SynthesisError},
};

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

impl<F: Field> IsWitness<F> for UInt128<F> {}

impl<F: Field> FromBytesGadget<F> for UInt128<F> {
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

impl<F: Field> BitwiseOperationGadget<F> for UInt128<F> {
    fn and(&self, other_gadget: Self) -> Result<Self>
    where
        Self: std::marker::Sized,
    {
        let result = zip_bits_and_apply(
            self.to_bits_le(),
            other_gadget.to_bits_le(),
            |first_bit, second_bit| first_bit.and(&second_bit),
        )?;
        let new_value = UInt128::from_bits_le(&result);
        Ok(new_value)
    }

    fn nand(&self, other_gadget: Self) -> Result<Self>
    where
        Self: std::marker::Sized,
    {
        let result = zip_bits_and_apply(
            self.to_bits_le(),
            other_gadget.to_bits_le(),
            |first_bit, second_bit| Ok(first_bit.and(&second_bit)?.not()),
        )?;
        let new_value = UInt128::from_bits_le(&result);
        Ok(new_value)
    }

    fn nor(&self, other_gadget: Self) -> Result<Self>
    where
        Self: std::marker::Sized + ToBitsGadget<F>,
    {
        let result = zip_bits_and_apply(
            self.to_bits_le(),
            other_gadget.to_bits_le(),
            |first_bit, second_bit| Ok(first_bit.or(&second_bit)?.not()),
        )?;
        let new_value = UInt128::from_bits_le(&result);
        Ok(new_value)
    }

    fn or(&self, other_gadget: Self) -> Result<Self>
    where
        Self: std::marker::Sized + ToBitsGadget<F>,
    {
        let result = zip_bits_and_apply(
            self.to_bits_le(),
            other_gadget.to_bits_le(),
            |first_bit, second_bit| first_bit.or(&second_bit),
        )?;
        let new_value = UInt128::from_bits_le(&result);
        Ok(new_value)
    }

    fn xor(&self, other_gadget: Self) -> Result<Self>
    where
        Self: std::marker::Sized,
    {
        let result = zip_bits_and_apply(
            self.to_bits_le(),
            other_gadget.to_bits_le(),
            |first_bit, second_bit| first_bit.xor(&second_bit),
        )?;
        let new_value = UInt128::from_bits_le(&result);
        Ok(new_value)
    }

    fn rotate_left(
        &self,
        positions: usize,
        constraint_system: ConstraintSystemRef<F>,
    ) -> Result<Self> {
        let mut primitive_bits = self.to_bits_le();
        primitive_bits.reverse();
        let mut rotated_bits = primitive_bits.clone();
        rotated_bits.rotate_left(positions);

        for i in 0..128 {
            if let (Some(a), Some(b)) = (
                &primitive_bits.get((i + positions) % 128),
                &rotated_bits.get(i),
            ) {
                let c = lc!() + a.lc() - b.lc();
                constraint_system.enforce_constraint(lc!(), lc!(), c)?
            }
        }

        rotated_bits.reverse();
        Ok(UInt128::<F>::from_bits_le(&rotated_bits))
    }

    fn rotate_right(
        &self,
        positions: usize,
        constraint_system: ConstraintSystemRef<F>,
    ) -> Result<Self> {
        // Example: rotate one place to the right is the same as rotate 7 places
        // to the left while generating the same number of constraints.
        // We compute positions % 128 to avoid subtraction overflow when someone
        // tries to rotate more then 128 positions.
        self.rotate_left(128 - (positions % 128), constraint_system)
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
        let shifted_value = UInt128::<F>::new_witness(constraint_system.clone(), || {
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

        if positions >= 128 {
            for c in shifted_bits.iter() {
                constraint_system.enforce_constraint(lc!(), lc!(), c.lc())?;
            }
        } else {
            // Check that the last positions bits are 0s.
            shifted_bits
                .iter()
                .skip(128 - (positions % 128))
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
        let shifted_value = UInt128::<F>::new_witness(constraint_system.clone(), || {
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

        if positions >= 128 {
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

#[cfg(test)]
mod tests {
    use crate::gadgets::{traits::BitwiseOperationGadget, ConstraintF, UInt128Gadget};
    use ark_r1cs_std::{prelude::AllocVar, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_one_left_rotation() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let byte = UInt128Gadget::new_witness(cs.clone(), || Ok(0b1000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000)).unwrap();
        let positions_to_rotate = 1;
        let expected_byte = byte.value().unwrap().rotate_left(positions_to_rotate);

        let result = byte
            .rotate_left(positions_to_rotate.try_into().unwrap(), cs.clone())
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(expected_byte, result.value().unwrap());
        assert_eq!(result.value().unwrap(), 1);
    }

    #[test]
    fn test_more_than_one_left_rotation() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let byte = UInt128Gadget::new_witness(cs.clone(), || Ok(0b1000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000)).unwrap();
        let positions_to_rotate = 2;
        let expected_byte = byte.value().unwrap().rotate_left(positions_to_rotate);

        let result = byte
            .rotate_left(positions_to_rotate.try_into().unwrap(), cs.clone())
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(expected_byte, result.value().unwrap());
        assert_eq!(result.value().unwrap(), 2);
    }

    #[test]
    fn test_one_right_rotation() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let byte = UInt128Gadget::new_witness(cs.clone(), || Ok(2)).unwrap();
        let positions_to_rotate = 1;
        let expected_byte = byte.value().unwrap().rotate_right(positions_to_rotate);

        let result = byte
            .rotate_right(positions_to_rotate.try_into().unwrap(), cs.clone())
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(expected_byte, result.value().unwrap());
        assert_eq!(result.value().unwrap(), 1);
    }

    #[test]
    fn test_more_than_one_right_rotation() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let byte = UInt128Gadget::new_witness(cs.clone(), || Ok(2)).unwrap();
        let positions_to_rotate = 2;
        let expected_byte = byte.value().unwrap().rotate_right(positions_to_rotate);

        let result = byte
            .rotate_right(positions_to_rotate.try_into().unwrap(), cs.clone())
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(expected_byte, result.value().unwrap());
        assert_eq!(result.value().unwrap(), 0b1000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000);
    }

    #[test]
    fn test_one_left_shift() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let byte = UInt128Gadget::new_witness(cs.clone(), || Ok(1)).unwrap();
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
        let byte = UInt128Gadget::new_witness(cs.clone(), || Ok(1)).unwrap();
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
        let byte = UInt128Gadget::new_witness(cs.clone(), || Ok(0b1000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0001)).unwrap();
        let positions_to_shift = 1_i32;
        let expected_byte = UInt128Gadget::constant(2).value().unwrap();

        let result = byte
            .shift_left(positions_to_shift.try_into().unwrap(), cs.clone())
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(expected_byte, result.value().unwrap());
    }

    #[test]
    fn test_overflow_all_bits_left_shift() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let byte = UInt128Gadget::new_witness(cs.clone(), || Ok(1)).unwrap();
        let positions_to_shift = 128_i32;
        let expected_byte = 0_u128;

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
        let byte = UInt128Gadget::new_witness(cs.clone(), || Ok(2)).unwrap();
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
        let byte = UInt128Gadget::new_witness(cs.clone(), || Ok(4)).unwrap();
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
        let byte = UInt128Gadget::new_witness(cs.clone(), || Ok(1)).unwrap();
        let positions_to_shift = 1_i32;
        let expected_byte = UInt128Gadget::constant(0).value().unwrap();

        let result = byte
            .shift_right(positions_to_shift.try_into().unwrap(), cs.clone())
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(expected_byte, result.value().unwrap());
    }

    #[test]
    fn test_overflow_all_bits_right_shift() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let byte = UInt128Gadget::new_witness(cs.clone(), || Ok(u128::MAX)).unwrap();
        let positions_to_shift = 128_i32;
        let expected_byte = 0_u128;

        let result = byte
            .shift_right(positions_to_shift.try_into().unwrap(), cs.clone())
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(expected_byte, result.value().unwrap());
    }
}
