use anyhow::{anyhow, Result};
use ark_ff::Field;
use ark_r1cs_std::{prelude::Boolean, uint8::UInt8, ToBitsGadget, ToBytesGadget};
use ark_relations::r1cs::ConstraintSystemRef;

use super::Comparison;

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

        bit.is_witness()
    }
}

pub trait FromBytesGadget<F: Field> {
    fn from_bytes_le(bytes: &[UInt8<F>]) -> Result<Self>
    where
        Self: Sized;

    fn from_bytes_be(bytes: &[UInt8<F>]) -> Result<Self>
    where
        Self: Sized;
}

pub trait ByteManipulationGadget<F: Field> {
    fn rotate_left(
        &self,
        positions: usize,
        constraint_system: ConstraintSystemRef<F>,
    ) -> Result<Self>
    where
        Self: std::marker::Sized;

    fn rotate_right(
        &self,
        positions: usize,
        constraint_system: ConstraintSystemRef<F>,
    ) -> Result<Self>
    where
        Self: std::marker::Sized;
}

pub trait BitManipulationGadget<F: Field> {
    fn shift_left(
        &self,
        positions: usize,
        constraint_system: ConstraintSystemRef<F>,
    ) -> Result<Self>
    where
        Self: std::marker::Sized;

    fn shift_right(
        &self,
        positions: usize,
        constraint_system: ConstraintSystemRef<F>,
    ) -> Result<Self>
    where
        Self: std::marker::Sized;

    fn rotate_left(
        &self,
        positions: usize,
        constraint_system: ConstraintSystemRef<F>,
    ) -> Result<Self>
    where
        Self: std::marker::Sized;

    fn rotate_right(
        &self,
        positions: usize,
        constraint_system: ConstraintSystemRef<F>,
    ) -> Result<Self>
    where
        Self: std::marker::Sized;
}

pub trait BitwiseOperationGadget<F: Field> {
    fn and(&self, other_gadget: &Self) -> Result<Self>
    where
        Self: std::marker::Sized;

    fn or(&self, other_gadget: &Self) -> Result<Self>
    where
        Self: std::marker::Sized;

    fn nand(&self, other_gadget: &Self) -> Result<Self>
    where
        Self: std::marker::Sized;

    fn nor(&self, other_gadget: &Self) -> Result<Self>
    where
        Self: std::marker::Sized;

    fn xor(&self, other_gadget: &Self) -> Result<Self>
    where
        Self: std::marker::Sized;
}

pub trait ArithmeticGadget<F: Field> {
    fn add(&self, addend: &Self) -> Result<Self>
    where
        Self: std::marker::Sized;

    fn sub(&self, subtrahend: &Self) -> Result<Self>
    where
        Self: std::marker::Sized;

    fn mul(&self, multiplicand: &Self, constraint_system: ConstraintSystemRef<F>) -> Result<Self>
    where
        Self: std::marker::Sized;

    fn div(&self, divisor: &Self, constraint_system: ConstraintSystemRef<F>) -> Result<Self>
    where
        Self: std::marker::Sized;
}

pub trait ComparisonGadget<F: Field> {
    fn compare(
        &self,
        gadget_to_compare: &Self,
        comparison: Comparison,
        constraint_system: ConstraintSystemRef<F>,
    ) -> Result<Boolean<F>>
    where
        Self: std::marker::Sized;
}

/* ToFieldElements implementations */

impl<F: Field> ToFieldElements<F> for u8 {
    fn to_field_elements(&self) -> Result<Vec<F>> {
        let field_elements = (0_u8..8_u8)
            .into_iter()
            .map(|bit_index| {
                if (self >> bit_index) & 1 == 1 {
                    F::one()
                } else {
                    F::zero()
                }
            })
            .collect::<Vec<F>>();
        Ok(field_elements)
    }
}

impl<F: Field> ToFieldElements<F> for u16 {
    fn to_field_elements(&self) -> Result<Vec<F>> {
        let field_elements = (0_u16..16_u16)
            .into_iter()
            .map(|bit_index| {
                if self >> bit_index & 1 == 1 {
                    F::one()
                } else {
                    F::zero()
                }
            })
            .collect::<Vec<F>>();
        Ok(field_elements)
    }
}

impl<F: Field> ToFieldElements<F> for u32 {
    fn to_field_elements(&self) -> Result<Vec<F>> {
        let field_elements = (0_u32..32_u32)
            .into_iter()
            .map(|bit_index| {
                if self >> bit_index & 1 == 1 {
                    F::one()
                } else {
                    F::zero()
                }
            })
            .collect::<Vec<F>>();
        Ok(field_elements)
    }
}

impl<F: Field> ToFieldElements<F> for u64 {
    fn to_field_elements(&self) -> Result<Vec<F>> {
        let field_elements = (0_u64..64_u64)
            .into_iter()
            .map(|bit_index| {
                if self >> bit_index & 1 == 1 {
                    F::one()
                } else {
                    F::zero()
                }
            })
            .collect::<Vec<F>>();
        Ok(field_elements)
    }
}

impl<F: Field> ToFieldElements<F> for u128 {
    fn to_field_elements(&self) -> Result<Vec<F>> {
        let field_elements = (0_u128..128_u128)
            .into_iter()
            .map(|bit_index| {
                if self >> bit_index & 1 == 1 {
                    F::one()
                } else {
                    F::zero()
                }
            })
            .collect::<Vec<F>>();
        Ok(field_elements)
    }
}

impl<F: Field> ToFieldElements<F> for i8 {
    fn to_field_elements(&self) -> Result<Vec<F>> {
        let field_elements = (0_i8..8_i8)
            .into_iter()
            .map(|bit_index| {
                if self >> bit_index & 1 == 1 {
                    F::one()
                } else {
                    F::zero()
                }
            })
            .collect::<Vec<F>>();
        Ok(field_elements)
    }
}

impl<F: Field> ToFieldElements<F> for [u8; 63] {
    fn to_field_elements(&self) -> Result<Vec<F>> {
        let mut field_elements = Vec::with_capacity(63 * 8);
        for byte in self.iter() {
            field_elements.extend_from_slice(&ToFieldElements::<F>::to_field_elements(byte)?);
        }
        Ok(field_elements)
    }
}

#[cfg(test)]
mod test {
    use super::ToFieldElements;
    use crate::gadgets::ConstraintF;
    use ark_ff::{One, Zero};

    #[test]
    fn test_u8_to_field_elements() {
        let number = u8::MAX;
        let expected_field_elements: Vec<ConstraintF> = vec![ConstraintF::one(); 8];

        assert_eq!(
            expected_field_elements,
            ToFieldElements::<ConstraintF>::to_field_elements(&number).unwrap()
        )
    }

    #[test]
    fn test_u8_to_field_elements_is_little_endian() {
        let number = 142_u8;
        let expected_field_elements: Vec<ConstraintF> = vec![
            ConstraintF::zero(),
            ConstraintF::one(),
            ConstraintF::one(),
            ConstraintF::one(),
            ConstraintF::zero(),
            ConstraintF::zero(),
            ConstraintF::zero(),
            ConstraintF::one(),
        ];

        assert_eq!(
            expected_field_elements,
            ToFieldElements::<ConstraintF>::to_field_elements(&number).unwrap()
        )
    }

    #[test]
    fn test_u16_to_field_elements() {
        let number = u16::MAX;
        let expected_field_elements: Vec<ConstraintF> = vec![ConstraintF::one(); 16];

        assert_eq!(
            expected_field_elements,
            ToFieldElements::<ConstraintF>::to_field_elements(&number).unwrap()
        )
    }

    #[test]
    fn test_u16_to_field_elements_is_little_endian() {
        let number = 0b0000_0001_1010_0001_u16;
        let expected_field_elements: Vec<ConstraintF> = vec![
            ConstraintF::one(),
            ConstraintF::zero(),
            ConstraintF::zero(),
            ConstraintF::zero(),
            ConstraintF::zero(),
            ConstraintF::one(),
            ConstraintF::zero(),
            ConstraintF::one(),
            ConstraintF::one(),
            ConstraintF::zero(),
            ConstraintF::zero(),
            ConstraintF::zero(),
            ConstraintF::zero(),
            ConstraintF::zero(),
            ConstraintF::zero(),
            ConstraintF::zero(),
        ];

        assert_eq!(
            expected_field_elements,
            ToFieldElements::<ConstraintF>::to_field_elements(&number).unwrap()
        )
    }

    #[test]
    fn test_u32_to_field_elements() {
        let number = u32::MAX;
        let expected_field_elements: Vec<ConstraintF> = vec![ConstraintF::one(); 32];

        assert_eq!(
            expected_field_elements,
            ToFieldElements::<ConstraintF>::to_field_elements(&number).unwrap()
        )
    }

    #[test]
    fn test_u32_to_field_elements_is_little_endian() {
        // Big endian
        let number = 0b1000_0000_0000_0000_0000_0000_0000_0000_u32;
        // Little endian
        let mut expected_field_elements: Vec<ConstraintF> = vec![ConstraintF::zero(); 31];
        expected_field_elements.extend_from_slice(&[ConstraintF::one()]);

        assert_eq!(
            expected_field_elements,
            ToFieldElements::<ConstraintF>::to_field_elements(&number).unwrap()
        )
    }

    #[test]
    fn test_u64_to_field_elements() {
        let number = u64::MAX;
        let expected_field_elements: Vec<ConstraintF> = vec![ConstraintF::one(); 64];

        assert_eq!(
            expected_field_elements,
            ToFieldElements::<ConstraintF>::to_field_elements(&number).unwrap()
        )
    }

    #[test]
    fn test_u64_to_field_elements_is_little_endian() {
        // Big endian
        let number =
            0b1000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_u64;
        // Little endian
        let mut expected_field_elements: Vec<ConstraintF> = vec![ConstraintF::zero(); 63];
        expected_field_elements.extend_from_slice(&[ConstraintF::one()]);

        assert_eq!(
            expected_field_elements,
            ToFieldElements::<ConstraintF>::to_field_elements(&number).unwrap()
        )
    }

    #[test]
    fn test_u128_to_field_elements() {
        let number = u128::MAX;
        let expected_field_elements: Vec<ConstraintF> = vec![ConstraintF::one(); 128];

        assert_eq!(
            expected_field_elements,
            ToFieldElements::<ConstraintF>::to_field_elements(&number).unwrap()
        )
    }

    #[test]
    fn test_u128_to_field_elements_is_little_endian() {
        // Big endian
        let number = 0b1000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_u128;
        // Little endian
        let mut expected_field_elements: Vec<ConstraintF> = vec![ConstraintF::zero(); 127];
        expected_field_elements.extend_from_slice(&[ConstraintF::one()]);

        assert_eq!(
            expected_field_elements,
            ToFieldElements::<ConstraintF>::to_field_elements(&number).unwrap()
        )
    }

    #[test]
    fn test_i8_to_field_elements() {
        let number = i8::MAX;
        let mut expected_field_elements: Vec<ConstraintF> = vec![ConstraintF::one(); 7];
        expected_field_elements.push(ConstraintF::zero());

        assert_eq!(
            expected_field_elements,
            ToFieldElements::<ConstraintF>::to_field_elements(&number).unwrap()
        )
    }

    #[test]
    fn test_i8_positive_to_field_elements_is_little_endian() {
        let number = 64_i8;
        let expected_field_elements: Vec<ConstraintF> = vec![
            ConstraintF::zero(),
            ConstraintF::zero(),
            ConstraintF::zero(),
            ConstraintF::zero(),
            ConstraintF::zero(),
            ConstraintF::zero(),
            ConstraintF::one(),
            ConstraintF::zero(),
        ];

        assert_eq!(
            expected_field_elements,
            ToFieldElements::<ConstraintF>::to_field_elements(&number).unwrap()
        )
    }

    #[test]
    fn test_i8_negative_to_field_elements_is_little_endian() {
        let number = -64_i8;
        let expected_field_elements: Vec<ConstraintF> = vec![
            ConstraintF::zero(),
            ConstraintF::zero(),
            ConstraintF::zero(),
            ConstraintF::zero(),
            ConstraintF::zero(),
            ConstraintF::zero(),
            ConstraintF::one(),
            ConstraintF::one(),
        ];

        assert_eq!(
            expected_field_elements,
            ToFieldElements::<ConstraintF>::to_field_elements(&number).unwrap()
        )
    }

    #[test]
    fn test_address_to_field_elements() {
        let mut address = [0_u8; 63];
        let address_str = b"aleo11111111111111111111111111111111111111111111111111111111111";
        for (sender_address_byte, address_string_byte) in address.iter_mut().zip(address_str) {
            *sender_address_byte = *address_string_byte;
        }

        // "a"
        let mut expected_field_elements = vec![
            ConstraintF::one(),
            ConstraintF::zero(),
            ConstraintF::zero(),
            ConstraintF::zero(),
            ConstraintF::zero(),
            ConstraintF::one(),
            ConstraintF::one(),
            ConstraintF::zero(),
        ];

        // "l"
        expected_field_elements.extend_from_slice(&[
            ConstraintF::zero(),
            ConstraintF::zero(),
            ConstraintF::one(),
            ConstraintF::one(),
            ConstraintF::zero(),
            ConstraintF::one(),
            ConstraintF::one(),
            ConstraintF::zero(),
        ]);

        // "e"
        expected_field_elements.extend_from_slice(&[
            ConstraintF::one(),
            ConstraintF::zero(),
            ConstraintF::one(),
            ConstraintF::zero(),
            ConstraintF::zero(),
            ConstraintF::one(),
            ConstraintF::one(),
            ConstraintF::zero(),
        ]);

        // "o"
        expected_field_elements.extend_from_slice(&[
            ConstraintF::one(),
            ConstraintF::one(),
            ConstraintF::one(),
            ConstraintF::one(),
            ConstraintF::zero(),
            ConstraintF::one(),
            ConstraintF::one(),
            ConstraintF::zero(),
        ]);

        // 59 "1"s
        expected_field_elements.extend_from_slice(
            &vec![
                vec![
                    ConstraintF::one(),
                    ConstraintF::zero(),
                    ConstraintF::zero(),
                    ConstraintF::zero(),
                    ConstraintF::one(),
                    ConstraintF::one(),
                    ConstraintF::zero(),
                    ConstraintF::zero(),
                ];
                59
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<ConstraintF>>(),
        );

        assert_eq!(expected_field_elements.len(), address.len() * 8);
        assert_eq!(
            expected_field_elements,
            ToFieldElements::<ConstraintF>::to_field_elements(&address).unwrap()
        )
    }
}
