use super::traits::{
    BitRotationGadget, BitShiftGadget, ByteRotationGadget, IsWitness, ToFieldElements,
};
use anyhow::Result;
use ark_ff::Field;
use ark_r1cs_std::{prelude::AllocVar, uint8::UInt8, R1CSVar, ToBitsGadget};
use ark_relations::{
    lc,
    r1cs::{ConstraintSystemRef, SynthesisError},
};

impl<F: Field> ToFieldElements<F> for UInt8<F> {
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

impl<F: Field> IsWitness<F> for [UInt8<F>] {}

impl<F: Field> BitRotationGadget<F> for UInt8<F> {
    fn rotate_left(
        &self,
        positions: usize,
        constraint_system: ConstraintSystemRef<F>,
    ) -> Result<Self> {
        let primitive_bits = self.to_bits_be()?;
        let mut rotated_bits = primitive_bits.clone();
        rotated_bits.rotate_left(positions);

        for i in 0..8 {
            let a = &primitive_bits[(i + positions) % 8];
            let b = &rotated_bits[i];
            let c = lc!() + a.lc() - b.lc();
            constraint_system.enforce_constraint(lc!(), lc!(), c)?
        }

        rotated_bits.reverse();
        Ok(UInt8::<F>::from_bits_le(&rotated_bits))
    }

    fn rotate_right(
        &self,
        positions: usize,
        constraint_system: ConstraintSystemRef<F>,
    ) -> Result<Self> {
        // Example: rotate one place to the right is the same as rotate 7 places
        // to the left while generating the same number of constraints.
        // We compute positions % 8 to avoid subtraction overflow when someone
        // tries to rotate more then 8 positions.
        self.rotate_left(8 - (positions % 8), constraint_system)
    }
}

impl<F: Field> ByteRotationGadget<F> for [UInt8<F>; 4] {
    fn rotate_left(
        &self,
        positions: usize,
        constraint_system: ConstraintSystemRef<F>,
    ) -> Result<Self> {
        let primitive_bits = self.to_bits_be()?;
        let mut rotated_bits = primitive_bits.clone();
        let adjusted_positions = 32 - ((positions * 8) % 32);
        rotated_bits.rotate_left(adjusted_positions);

        for i in 0..self.len() {
            let a = &primitive_bits[(i + adjusted_positions) % 32];
            let b = &rotated_bits[i];
            let c = lc!() + a.lc() - b.lc();
            constraint_system.enforce_constraint(lc!(), lc!(), c)?
        }

        rotated_bits.reverse();
        let mut result = [
            UInt8::<F>::constant(0),
            UInt8::<F>::constant(0),
            UInt8::<F>::constant(0),
            UInt8::<F>::constant(0),
        ];
        for (result_byte, result_chunk_byte) in result.iter_mut().zip(rotated_bits.chunks(8)) {
            *result_byte = UInt8::<F>::from_bits_le(result_chunk_byte);
        }

        Ok(result)
    }

    fn rotate_right(
        &self,
        positions: usize,
        constraint_system: ConstraintSystemRef<F>,
    ) -> Result<Self> {
        // Example: rotate one place to the right is the same as rotate 7 places
        // to the left while generating the same number of constraints.
        // We compute positions % 8 to avoid subtraction overflow when someone
        // tries to rotate more then 8 positions.
        self.rotate_left(32 - (positions % 32), constraint_system)
    }
}

impl<F: Field> BitShiftGadget<F> for UInt8<F> {
    fn shift_left(
        &self,
        positions: usize,
        constraint_system: ConstraintSystemRef<F>,
    ) -> Result<Self>
    where
        Self: std::marker::Sized,
    {
        let primitive_bits = self.to_bits_be()?;
        let shifted_value = UInt8::<F>::new_witness(constraint_system.clone(), || {
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
        let shifted_bits = shifted_value.to_bits_be()?;

        if positions >= 8 {
            for c in shifted_bits.iter() {
                constraint_system.enforce_constraint(lc!(), lc!(), c.lc())?;
            }
        } else {
            // Check that the last positions bits are 0s.
            shifted_bits
                .iter()
                .skip(8 - (positions % 8))
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
        let primitive_bits = self.to_bits_be()?;
        let shifted_value = UInt8::<F>::new_witness(constraint_system.clone(), || {
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
        let shifted_bits = shifted_value.to_bits_be()?;

        if positions >= 8 {
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
    use crate::gadgets::{
        traits::{BitRotationGadget, BitShiftGadget, ByteRotationGadget},
        ConstraintF, UInt8Gadget,
    };
    use ark_r1cs_std::{prelude::AllocVar, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_one_left_rotation() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let byte = UInt8Gadget::new_witness(cs.clone(), || Ok(142)).unwrap();
        let positions_to_rotate = 1;
        let expected_byte = byte.value().unwrap().rotate_left(positions_to_rotate);

        let result = byte
            .rotate_left(positions_to_rotate.try_into().unwrap(), cs.clone())
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(expected_byte, result.value().unwrap());
    }

    #[test]
    fn test_more_than_one_left_rotation() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let byte = UInt8Gadget::new_witness(cs.clone(), || Ok(142)).unwrap();
        let positions_to_rotate = 2;
        let expected_byte = byte.value().unwrap().rotate_left(positions_to_rotate);

        let result = byte
            .rotate_left(positions_to_rotate.try_into().unwrap(), cs.clone())
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(expected_byte, result.value().unwrap());
    }

    #[test]
    fn test_one_right_rotation() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let byte = UInt8Gadget::new_witness(cs.clone(), || Ok(135)).unwrap();
        let positions_to_rotate = 1;
        let expected_byte = byte.value().unwrap().rotate_right(positions_to_rotate);

        let result = byte
            .rotate_right(positions_to_rotate.try_into().unwrap(), cs.clone())
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(expected_byte, result.value().unwrap());
    }

    #[test]
    fn test_more_than_one_right_rotation() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let byte = UInt8Gadget::new_witness(cs.clone(), || Ok(135)).unwrap();
        let positions_to_rotate = 2;
        let expected_byte = byte.value().unwrap().rotate_right(positions_to_rotate);

        let result = byte
            .rotate_right(positions_to_rotate.try_into().unwrap(), cs.clone())
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(expected_byte, result.value().unwrap());
    }

    #[test]
    fn test_one_left_shift() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let byte = UInt8Gadget::new_witness(cs.clone(), || Ok(1)).unwrap();
        let positions_to_shift = 1;
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
        let byte = UInt8Gadget::new_witness(cs.clone(), || Ok(1)).unwrap();
        let positions_to_shift = 2;
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
        let byte = UInt8Gadget::new_witness(cs.clone(), || Ok(0b1000_0001)).unwrap();
        let positions_to_shift = 1;
        let expected_byte = UInt8Gadget::constant(2).value().unwrap();

        let result = byte
            .shift_left(positions_to_shift.try_into().unwrap(), cs.clone())
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(expected_byte, result.value().unwrap());
    }

    #[test]
    fn test_overflow_all_bits_left_shift() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let byte = UInt8Gadget::new_witness(cs.clone(), || Ok(1)).unwrap();
        let positions_to_shift = 8;
        let expected_byte = 0;

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
        let byte = UInt8Gadget::new_witness(cs.clone(), || Ok(2)).unwrap();
        let positions_to_shift = 1;
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
        let byte = UInt8Gadget::new_witness(cs.clone(), || Ok(4)).unwrap();
        let positions_to_shift = 2;
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
        let byte = UInt8Gadget::new_witness(cs.clone(), || Ok(1)).unwrap();
        let positions_to_shift = 1;
        let expected_byte = UInt8Gadget::constant(0).value().unwrap();

        let result = byte
            .shift_right(positions_to_shift.try_into().unwrap(), cs.clone())
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(expected_byte, result.value().unwrap());
    }

    #[test]
    fn test_overflow_all_bits_right_shift() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let byte = UInt8Gadget::new_witness(cs.clone(), || Ok(u8::MAX)).unwrap();
        let positions_to_shift = 8;
        let expected_byte = 0;

        let result = byte
            .shift_right(positions_to_shift.try_into().unwrap(), cs.clone())
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(expected_byte, result.value().unwrap());
    }

    #[test]
    fn test_not_rotating_a_byte_to_the_left_should_return_the_original_byte() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let bytes = [
            UInt8Gadget::new_witness(cs.clone(), || Ok(1)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(2)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(3)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(4)).unwrap(),
        ];
        let expected_rotated_bytes = bytes.clone();

        let rotated_byte = bytes.rotate_left(0, cs.clone()).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            rotated_byte.value().unwrap(),
            expected_rotated_bytes.value().unwrap()
        )
    }

    #[test]
    fn test_one_byte_left_rotation() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let bytes = [
            UInt8Gadget::new_witness(cs.clone(), || Ok(1)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(2)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(3)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(4)).unwrap(),
        ];
        let expected_rotated_bytes = [
            UInt8Gadget::new_witness(cs.clone(), || Ok(2)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(3)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(4)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(1)).unwrap(),
        ];

        let rotated_byte = bytes.rotate_left(1, cs.clone()).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            rotated_byte.value().unwrap(),
            expected_rotated_bytes.value().unwrap()
        )
    }

    #[test]
    fn test_more_than_one_byte_left_rotation() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let bytes = [
            UInt8Gadget::new_witness(cs.clone(), || Ok(1)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(2)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(3)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(4)).unwrap(),
        ];
        let expected_rotated_bytes = [
            UInt8Gadget::new_witness(cs.clone(), || Ok(3)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(4)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(1)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(2)).unwrap(),
        ];

        let rotated_byte = bytes.rotate_left(2, cs.clone()).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            rotated_byte.value().unwrap(),
            expected_rotated_bytes.value().unwrap()
        )
    }

    #[test]
    fn test_overflowing_byte_left_rotation() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let bytes = [
            UInt8Gadget::new_witness(cs.clone(), || Ok(1)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(2)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(3)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(4)).unwrap(),
        ];
        let expected_rotated_bytes = bytes.clone();

        let rotated_byte = bytes.rotate_left(4, cs.clone()).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            rotated_byte.value().unwrap(),
            expected_rotated_bytes.value().unwrap()
        )
    }

    #[test]
    fn test_not_rotating_a_byte_to_the_right_should_return_the_original_byte() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let bytes = [
            UInt8Gadget::new_witness(cs.clone(), || Ok(1)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(2)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(3)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(4)).unwrap(),
        ];

        let rotated_byte = bytes.rotate_right(0, cs.clone()).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(rotated_byte.value().unwrap(), bytes.value().unwrap())
    }

    #[test]
    fn test_one_byte_right_rotation() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let bytes = [
            UInt8Gadget::new_witness(cs.clone(), || Ok(1)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(2)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(3)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(4)).unwrap(),
        ];
        let expected_rotated_bytes = [
            UInt8Gadget::new_witness(cs.clone(), || Ok(4)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(1)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(2)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(3)).unwrap(),
        ];

        let rotated_byte = bytes.rotate_right(1, cs.clone()).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            rotated_byte.value().unwrap(),
            expected_rotated_bytes.value().unwrap()
        )
    }

    #[test]
    fn test_more_than_one_byte_right_rotation() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let bytes = [
            UInt8Gadget::new_witness(cs.clone(), || Ok(1)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(2)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(3)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(4)).unwrap(),
        ];
        let expected_rotated_bytes = [
            UInt8Gadget::new_witness(cs.clone(), || Ok(3)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(4)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(1)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(2)).unwrap(),
        ];

        let rotated_byte = bytes.rotate_right(2, cs.clone()).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            rotated_byte.value().unwrap(),
            expected_rotated_bytes.value().unwrap()
        )
    }

    #[test]
    fn test_overflowing_byte_right_rotation() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let bytes = [
            UInt8Gadget::new_witness(cs.clone(), || Ok(1)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(2)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(3)).unwrap(),
            UInt8Gadget::new_witness(cs.clone(), || Ok(4)).unwrap(),
        ];
        let expected_rotated_bytes = bytes.clone();

        let rotated_byte = bytes.rotate_right(4, cs.clone()).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            rotated_byte.value().unwrap(),
            expected_rotated_bytes.value().unwrap()
        )
    }
}
