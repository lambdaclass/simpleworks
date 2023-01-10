use super::traits::{BitRotationGadget, IsWitness, ToFieldElements};
use anyhow::Result;
use ark_ff::Field;
use ark_r1cs_std::{uint8::UInt8, R1CSVar, ToBitsGadget};
use ark_relations::{lc, r1cs::ConstraintSystemRef};

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

#[cfg(test)]
mod tests {
    use crate::gadgets::{traits::BitRotationGadget, ConstraintF, UInt8Gadget};
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
        assert_eq!(result.value().unwrap(), 195);
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
        assert_eq!(result.value().unwrap(), 225);
    }
}
