use super::traits::{FromBytesGadget, IsWitness, ToFieldElements};
use anyhow::{ensure, Result};
use ark_ff::Field;
use ark_r1cs_std::{
    prelude::{AllocVar, AllocationMode, Boolean, EqGadget},
    select::CondSelectGadget,
    uint8::UInt8,
    R1CSVar, ToBitsGadget, ToBytesGadget,
};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use serde::ser::{Serialize, Serializer};
use std::borrow::Borrow;
use std::string::ToString;

/// Represents an interpretation of 8 `Boolean` objects as an
/// unsigned integer.
#[derive(Clone, Debug)]
pub struct Address<F: Field> {
    /// Little-endian representation: least significant bit first
    pub(crate) bytes: Vec<UInt8<F>>,
    pub(crate) value: Option<[u8; 63]>,
}

impl<ConstraintF: Field> Address<ConstraintF> {
    pub fn to_bytes_be(&self) -> Result<Vec<UInt8<ConstraintF>>> {
        let mut bits = self.to_bits_le()?;
        bits.reverse();

        let bytes_be = bits
            .chunks_mut(8)
            .map(|chunk| {
                chunk.reverse();
                UInt8::<ConstraintF>::from_bits_le(chunk)
            })
            .collect();

        Ok(bytes_be)
    }
}

impl<ConstraintF: Field> AllocVar<[u8; 63], ConstraintF> for Address<ConstraintF> {
    fn new_variable<T: Borrow<[u8; 63]>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let value = f().map(|f| *f.borrow()).ok();

        let mut address_as_bytes = vec![];
        if let Some(val) = value {
            for byte in val {
                address_as_bytes.push(UInt8::new_variable(cs.clone(), || Ok(byte), mode)?);
            }
        }

        Ok(Self {
            bytes: address_as_bytes,
            value,
        })
    }
}

impl<ConstraintF: Field> EqGadget<ConstraintF> for Address<ConstraintF> {
    fn is_eq(&self, other: &Self) -> Result<Boolean<ConstraintF>, SynthesisError> {
        self.bytes.is_eq(&other.bytes)
    }

    fn conditional_enforce_equal(
        &self,
        other: &Self,
        condition: &Boolean<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        self.bytes
            .conditional_enforce_equal(&other.bytes, condition)
    }

    fn conditional_enforce_not_equal(
        &self,
        other: &Self,
        condition: &Boolean<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        self.bytes
            .conditional_enforce_not_equal(&other.bytes, condition)
    }
}

impl<F: Field> R1CSVar<F> for Address<F> {
    type Value = String;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.bytes.as_slice().cs()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        let mut primitive_bytes = [0_u8; 63];
        for (primitive_byte, circuit_byte) in primitive_bytes.iter_mut().zip(&self.bytes) {
            *primitive_byte = circuit_byte.value()?;
        }

        debug_assert_eq!(self.value, Some(primitive_bytes));

        // TODO: Wrong error is returned.
        Ok(std::str::from_utf8(&primitive_bytes)
            .map_err(|_e| SynthesisError::AssignmentMissing)?
            .to_owned())
    }
}

impl<F: Field> ToFieldElements<F> for Address<F> {
    fn to_field_elements(&self) -> Result<Vec<F>> {
        let bits_le = self.bytes.to_bits_le()?;
        let mut result = Vec::with_capacity(63 * 8);
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

impl<ConstraintF: Field> ToString for Address<ConstraintF> {
    fn to_string(&self) -> String {
        let mut ret = String::with_capacity(63);
        if let Some(value) = self.value {
            for byte in value {
                let c = char::from_u32(byte.into()).unwrap_or(' ');
                ret.push(c);
            }
        }
        ret
    }
}

impl<ConstraintF: Field> Serialize for Address<ConstraintF> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let v = self.to_string();
        serializer.serialize_str(&v)
    }
}

impl<F: Field> ToBytesGadget<F> for Address<F> {
    fn to_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        Ok(self.bytes.clone())
    }
}

impl<F: Field> IsWitness<F> for Address<F> {}

impl<ConstraintF: Field> CondSelectGadget<ConstraintF> for Address<ConstraintF> {
    fn conditionally_select(
        cond: &Boolean<ConstraintF>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        let selected_bytes = true_value
            .bytes
            .iter()
            .zip(&false_value.bytes)
            .map(|(t, f)| UInt8::conditionally_select(cond, t, f));
        let mut bytes = vec![UInt8::constant(0); 63];
        for (result, new) in bytes.iter_mut().zip(selected_bytes) {
            *result = new?;
        }

        let value = cond.value().ok().and_then(|cond| {
            if cond {
                true_value.value
            } else {
                false_value.value
            }
        });

        Ok(Self { bytes, value })
    }
}

impl<F: Field> ToBitsGadget<F> for Address<F> {
    fn to_bits_le(&self) -> Result<Vec<Boolean<F>>, SynthesisError> {
        self.bytes.to_bits_le()
    }

    fn to_bits_be(&self) -> Result<Vec<Boolean<F>>, SynthesisError> {
        self.bytes.to_bits_be()
    }
}

impl<F: Field> FromBytesGadget<F> for Address<F> {
    fn from_bytes_le(bytes: &[UInt8<F>]) -> Result<Self>
    where
        Self: Sized,
    {
        ensure!(bytes.len() == 63, "Address must be 63 bytes long");
        let mut value = [0_u8; 63];
        for (primitive_byte, byte_gadget) in value.iter_mut().zip(bytes) {
            *primitive_byte = byte_gadget.value()?;
        }

        Ok(Self {
            bytes: bytes.to_vec(),
            value: Some(value),
        })
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

#[cfg(test)]
mod tests {
    use crate::gadgets::{traits::FromBytesGadget, ConstraintF};

    use super::super::AddressGadget;
    use ark_r1cs_std::{
        alloc::AllocVar, prelude::Boolean, select::CondSelectGadget, R1CSVar, ToBytesGadget,
    };
    use ark_relations::r1cs::{ConstraintSystem, Namespace};

    #[test]
    fn test_address_to_string() {
        let cs = ConstraintSystem::<ark_ed_on_bls12_377::Fq>::new_ref();
        let address = AddressGadget::new_witness(Namespace::new(cs.clone(), None), || {
            Ok(b"aleo11111111111111111111111111111111111111111111111111111111111")
        })
        .unwrap();

        let ret_str = address.to_string();
        assert_eq!(
            "aleo11111111111111111111111111111111111111111111111111111111111",
            ret_str
        );

        let address2 = AddressGadget::new_witness(Namespace::new(cs, None), || {
            Ok(b"aleo13rgfynqdpvega6f5gwvajt8w0cnrmvy0zzg9tqmuc5y4upk2vs9sgk3a3d")
        })
        .unwrap();

        let ret_str2 = address2.to_string();
        assert_eq!(
            "aleo13rgfynqdpvega6f5gwvajt8w0cnrmvy0zzg9tqmuc5y4upk2vs9sgk3a3d",
            ret_str2
        );

        let serialized = serde_json::to_string(&address2).unwrap();
        assert_eq!(
            "\"aleo13rgfynqdpvega6f5gwvajt8w0cnrmvy0zzg9tqmuc5y4upk2vs9sgk3a3d\"",
            serialized
        );
    }

    #[test]
    fn test_conditionally_select_true_value() {
        let cs = ConstraintSystem::<ark_ed_on_bls12_377::Fq>::new_ref();

        let condition = Boolean::<ConstraintF>::new_witness(cs.clone(), || Ok(true)).unwrap();
        let true_value = AddressGadget::new_witness(Namespace::new(cs.clone(), None), || {
            Ok(b"aleo11111111111111111111111111111111111111111111111111111111111")
        })
        .unwrap();
        let false_value = AddressGadget::new_witness(Namespace::new(cs, None), || {
            Ok(b"aleo13rgfynqdpvega6f5gwvajt8w0cnrmvy0zzg9tqmuc5y4upk2vs9sgk3a3d")
        })
        .unwrap();

        assert_eq!(
            AddressGadget::conditionally_select(&condition, &true_value, &false_value)
                .unwrap()
                .value()
                .unwrap(),
            true_value.value().unwrap()
        );
    }

    #[test]
    fn test_conditionally_select_false_value() {
        let cs = ConstraintSystem::<ark_ed_on_bls12_377::Fq>::new_ref();

        let condition = Boolean::<ConstraintF>::new_witness(cs.clone(), || Ok(false)).unwrap();
        let true_value = AddressGadget::new_witness(Namespace::new(cs.clone(), None), || {
            Ok(b"aleo11111111111111111111111111111111111111111111111111111111111")
        })
        .unwrap();
        let false_value = AddressGadget::new_witness(Namespace::new(cs, None), || {
            Ok(b"aleo13rgfynqdpvega6f5gwvajt8w0cnrmvy0zzg9tqmuc5y4upk2vs9sgk3a3d")
        })
        .unwrap();

        assert_eq!(
            AddressGadget::conditionally_select(&condition, &true_value, &false_value)
                .unwrap()
                .value()
                .unwrap(),
            false_value.value().unwrap()
        );
    }

    #[test]
    fn test_from_bytes_le_gadget() {
        let cs = ConstraintSystem::<ark_ed_on_bls12_377::Fq>::new_ref();

        let address = AddressGadget::new_witness(Namespace::new(cs, None), || {
            Ok(b"aleo11111111111111111111111111111111111111111111111111111111111")
        })
        .unwrap();
        let address_bytes = address.to_bytes().unwrap();

        let address_from_bytes = AddressGadget::from_bytes_le(&address_bytes).unwrap();

        assert_eq!(
            address.value().unwrap(),
            address_from_bytes.value().unwrap()
        );
    }

    #[test]
    fn test_from_bytes_be_gadget() {
        let cs = ConstraintSystem::<ark_ed_on_bls12_377::Fq>::new_ref();

        let address = AddressGadget::new_witness(Namespace::new(cs, None), || {
            Ok(b"aleo11111111111111111111111111111111111111111111111111111111111")
        })
        .unwrap();
        let address_bytes = address.to_bytes_be().unwrap();

        let address_from_bytes = AddressGadget::from_bytes_be(&address_bytes).unwrap();

        assert_eq!(
            address.value().unwrap(),
            address_from_bytes.value().unwrap()
        );
    }
}
