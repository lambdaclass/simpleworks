use ark_ff::Field;
use ark_r1cs_std::{
    prelude::{AllocVar, AllocationMode, Boolean, EqGadget},
    R1CSVar, uint8::UInt8,
};
use ark_relations::{
    r1cs::{ConstraintSystemRef, Namespace, SynthesisError},
};
use std::{borrow::Borrow, panic::UnwindSafe};

// use crate::errors::SimpleError;

/// Represents an interpretation of 8 `Boolean` objects as an
/// unsigned integer.
#[derive(Clone, Debug)]
pub struct Address<F: Field> {
    /// Little-endian representation: least significant bit first
    pub(crate) bytes: Vec<UInt8<F>>,
    pub(crate) value: Option<[u8; 63]>,
}

impl<F: Field> UnwindSafe for Address<F> {}

// impl<F: Field> Address<F> {
//     pub fn value(not_self: &Self) -> Result<String, SimpleError> {
//         std::panic::catch_unwind(|| R1CSVar::value(not_self));
//         Ok(String::new())
//     }
// }

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

        Ok(Self { bytes: address_as_bytes, value })
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
        self.bytes.conditional_enforce_equal(&other.bytes, condition)
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

        // TODO: We think that is better to unwrap here instead of raising the
        // wrong error (of type SynthesisError).
        #[allow(clippy::unwrap_used)]
        Ok(std::str::from_utf8(&primitive_bytes).unwrap().to_owned())
    }
}
