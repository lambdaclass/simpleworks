use anyhow::{anyhow, bail, Result};
use ark_ff::Field;
use std::convert::TryFrom;
use std::fmt;

use crate::gadgets::traits::ToFieldElements;
use crate::gadgets::ConstraintF;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum SimpleworksValueType {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    Address([u8; 63]),
    Record([u8; 63], u64),
}

impl TryFrom<&String> for SimpleworksValueType {
    type Error = anyhow::Error;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        if value.ends_with("u8") {
            let v = value.trim_end_matches("u8");
            let value_int = v.parse::<u8>().map_err(|e| anyhow!("{}", e))?;
            return Ok(SimpleworksValueType::U8(value_int));
        } else if value.ends_with("u16") {
            let v = value.trim_end_matches("u16");
            let value_int = v.parse::<u16>().map_err(|e| anyhow!("{}", e))?;
            return Ok(SimpleworksValueType::U16(value_int));
        } else if value.ends_with("u32") {
            let v = value.trim_end_matches("u32");
            let value_int = v.parse::<u32>().map_err(|e| anyhow!("{}", e))?;
            return Ok(SimpleworksValueType::U32(value_int));
        } else if value.ends_with("u64") {
            let v = value.trim_end_matches("u64");
            let value_int = v.parse::<u64>().map_err(|e| anyhow!("{}", e))?;
            return Ok(SimpleworksValueType::U64(value_int));
        } else if value.ends_with("u128") {
            let v = value.trim_end_matches("u128");
            let value_int = v.parse::<u128>().map_err(|e| anyhow!("{}", e))?;
            return Ok(SimpleworksValueType::U128(value_int));
        } else if value.starts_with("aleo1") {
            let v = value.trim_start_matches("aleo1");
            let mut address = [0_u8; 63];
            for (sender_address_byte, address_string_byte) in address.iter_mut().zip(v.as_bytes()) {
                *sender_address_byte = *address_string_byte;
            }
            return Ok(SimpleworksValueType::Address(address));
        }
        bail!("Unknown type")
    }
}

impl fmt::Display for SimpleworksValueType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SimpleworksValueType::U8(v) => write!(f, "{v}u8"),
            SimpleworksValueType::U16(v) => write!(f, "{v}u16"),
            SimpleworksValueType::U32(v) => write!(f, "{v}u32"),
            SimpleworksValueType::U64(v) => write!(f, "{v}u64"),
            SimpleworksValueType::U128(v) => write!(f, "{v}u128"),
            SimpleworksValueType::Address(v) => write!(f, "{:?}", v),
            SimpleworksValueType::Record(o, g) => {
                write!(f, "Record {{ owner: {:?}, gates: {} }}", o, g)
            }
        }
    }
}

impl ToFieldElements<ConstraintF> for SimpleworksValueType {
    fn to_field_elements(&self) -> Result<Vec<ConstraintF>> {
        match self {
            SimpleworksValueType::U8(value) => value.to_field_elements(),
            SimpleworksValueType::U16(value) => value.to_field_elements(),
            SimpleworksValueType::U32(value) => value.to_field_elements(),
            SimpleworksValueType::U64(value) => value.to_field_elements(),
            SimpleworksValueType::U128(value) => value.to_field_elements(),
            SimpleworksValueType::Address(value) => value.to_field_elements(),
            SimpleworksValueType::Record(_owner, _gates) => {
                bail!("Converting records to field elements is not supported")
            }
        }
    }
}

impl<F: Field> ToFieldElements<F> for u8 {
    fn to_field_elements(&self) -> Result<Vec<F>> {
        let field_elements = (0_u8..8_u8)
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

impl<F: Field> ToFieldElements<F> for [u8; 63] {
    fn to_field_elements(&self) -> Result<Vec<F>> {
        let mut field_elements = Vec::with_capacity(63 * 8);
        for byte in self.iter().rev() {
            field_elements.extend_from_slice(&ToFieldElements::<F>::to_field_elements(byte)?);
        }
        Ok(field_elements)
    }
}

#[cfg(test)]
mod tests {
    use super::SimpleworksValueType;
    use crate::gadgets::{traits::ToFieldElements, ConstraintF};
    use ark_ff::Zero;
    use ark_std::One;

    #[test]
    fn display_value() {
        let v = SimpleworksValueType::U8(2);
        let out = format!("{v}");
        assert_eq!(out, "2u8");
        let v = SimpleworksValueType::U16(3);
        let out = format!("{v}");
        assert_eq!(out, "3u16");
        let v = SimpleworksValueType::U32(4);
        let out = format!("{v}");
        assert_eq!(out, "4u32");
        let v = SimpleworksValueType::U64(5);
        let out = format!("{v}");
        assert_eq!(out, "5u64");
        let v = SimpleworksValueType::U128(6);
        let out = format!("{v}");
        assert_eq!(out, "6u128");
        // Address
        let mut address = [0_u8; 63];
        let address_str = "aleo1ecw94zggphqkpdsjhfjutr9p33nn9tk2d34tz23t29awtejupugq4vne6m";
        for (sender_address_byte, address_string_byte) in
            address.iter_mut().zip(address_str.as_bytes())
        {
            *sender_address_byte = *address_string_byte;
        }
        let v = SimpleworksValueType::Address(address);
        let out = format!("{v}");
        assert_eq!(out, format!("{:?}", address));
        // Record
        let mut address = [0_u8; 63];
        let address_str = "aleo1ecw94zggphqkpdsjhfjutr9p33nn9tk2d34tz23t29awtejupugq4vne6m";
        for (sender_address_byte, address_string_byte) in
            address.iter_mut().zip(address_str.as_bytes())
        {
            *sender_address_byte = *address_string_byte;
        }
        let gates = 1_u64;
        let v = SimpleworksValueType::Record(address, gates);
        let out = format!("{v}");
        assert_eq!(
            out,
            format!("Record {{ owner: {:?}, gates: {} }}", address, gates)
        );
    }

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
    fn test_address_to_field_elements() {
        let mut address = [0_u8; 63];
        let address_str = b"aleo11111111111111111111111111111111111111111111111111111111111";
        for (sender_address_byte, address_string_byte) in address.iter_mut().zip(address_str) {
            *sender_address_byte = *address_string_byte;
        }

        // 59 "1"s
        let mut expected_field_elements = vec![
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
        .collect::<Vec<ConstraintF>>();
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
        // "a"
        expected_field_elements.extend_from_slice(&[
            ConstraintF::one(),
            ConstraintF::zero(),
            ConstraintF::zero(),
            ConstraintF::zero(),
            ConstraintF::zero(),
            ConstraintF::one(),
            ConstraintF::one(),
            ConstraintF::zero(),
        ]);

        assert_eq!(expected_field_elements.len(), address.len() * 8);
        assert_eq!(
            expected_field_elements,
            ToFieldElements::<ConstraintF>::to_field_elements(&address).unwrap()
        )
    }
}
