use super::traits::ToFieldElements;
use anyhow::Result;
use ark_ff::Field;
use ark_r1cs_std::{
    prelude::{AllocVar, AllocationMode, Boolean, EqGadget},
    uint8::UInt8,
    R1CSVar, ToBitsGadget,
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

#[cfg(test)]
mod tests {
    use super::super::AddressGadget;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_relations::r1cs::{ConstraintSystem, Namespace};

    #[test]
    fn test_address_to_string() {
        let cs = ConstraintSystem::<ark_ed_on_bls12_381::Fq>::new_ref();
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
}
