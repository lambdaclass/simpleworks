use std::borrow::Borrow;

use crate::gadgets::Comparison;

use super::{
    helpers::{self, zip_bits_and_apply},
    traits::{
        ArithmeticGadget, BitManipulationGadget, BitwiseOperationGadget, ComparisonGadget,
        IsWitness,
    },
};
use anyhow::{anyhow, ensure, Result};
use ark_ff::Field;
use ark_r1cs_std::{
    prelude::{AllocVar, AllocationMode, Boolean, EqGadget},
    select::CondSelectGadget,
    uint8::UInt8,
    Assignment, R1CSVar, ToBitsGadget, ToBytesGadget,
};
use ark_relations::{
    lc,
    r1cs::{ConstraintSystemRef, Namespace, SynthesisError},
};

#[derive(Clone, Debug)]
pub struct Int8<F: Field> {
    pub(crate) bits: [Boolean<F>; 8],
    pub(crate) value: Option<i8>,
}

impl<F: Field> IsWitness<F> for Int8<F> {}

impl<F: Field> ToBytesGadget<F> for Int8<F> {
    fn to_bytes(&self) -> Result<Vec<ark_r1cs_std::uint8::UInt8<F>>, SynthesisError> {
        Ok(self
            .to_bits_le()?
            .chunks(8)
            .map(UInt8::from_bits_le)
            .collect())
    }
}

impl<ConstraintF: Field> AllocVar<i8, ConstraintF> for Int8<ConstraintF> {
    fn new_variable<T: Borrow<i8>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let value = f().map(|f| *f.borrow()).ok();

        let mut values = [None; 8];
        if let Some(val) = value {
            values
                .iter_mut()
                .enumerate()
                .for_each(|(i, v)| *v = Some((val >> i) & 1 == 1));
        }

        let mut bits = [Boolean::FALSE; 8];
        for (b, v) in bits.iter_mut().zip(&values) {
            *b = Boolean::new_variable(cs.clone(), || v.get(), mode)?;
        }
        Ok(Self { bits, value })
    }
}

impl<F: Field> R1CSVar<F> for Int8<F> {
    type Value = i8;

    fn cs(&self) -> ark_relations::r1cs::ConstraintSystemRef<F> {
        self.bits.as_ref().cs()
    }

    fn value(&self) -> Result<Self::Value, ark_relations::r1cs::SynthesisError> {
        let mut value = None;
        for (i, bit) in self.bits.iter().enumerate() {
            let b = i8::from(bit.value()?);
            value = match value {
                Some(value) => Some(value + (b << i)),
                None => Some(b << i),
            };
        }
        debug_assert_eq!(self.value, value);
        value.get()
    }
}

impl<F: Field> Int8<F> {
    pub fn constant(value: i8) -> Self {
        let mut bits = [Boolean::FALSE; 8];
        let mut tmp = value;
        for bit in &mut bits {
            *bit = Boolean::constant((tmp & 1) == 1);
            tmp >>= 1_i32;
        }
        Self {
            bits,
            value: Some(value),
        }
    }

    pub fn from_bits_le(bits: &[Boolean<F>]) -> Result<Self> {
        assert_eq!(bits.len(), 8, "Invalid array length, should be 8");
        let bits = <&[Boolean<F>; 8]>::try_from(bits)?.clone();

        let mut value = Some(0_i8);
        for (i, b) in bits.iter().enumerate() {
            value = match b.value().ok() {
                Some(b) => value.map(|v| v + (i8::from(b) << i)),
                None => None,
            }
        }

        Ok(Self { value, bits })
    }
}

impl<F: Field> ToBitsGadget<F> for Int8<F> {
    fn to_bits_le(&self) -> Result<Vec<Boolean<F>>, SynthesisError> {
        Ok(self.bits.to_vec())
    }
}

impl<ConstraintF: Field> EqGadget<ConstraintF> for Int8<ConstraintF> {
    #[tracing::instrument(target = "r1cs")]
    fn is_eq(&self, other: &Self) -> Result<Boolean<ConstraintF>, SynthesisError> {
        self.bits.as_ref().is_eq(&other.bits)
    }

    #[tracing::instrument(target = "r1cs")]
    fn conditional_enforce_equal(
        &self,
        other: &Self,
        condition: &Boolean<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        self.bits.conditional_enforce_equal(&other.bits, condition)
    }

    #[tracing::instrument(target = "r1cs")]
    fn conditional_enforce_not_equal(
        &self,
        other: &Self,
        condition: &Boolean<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        self.bits
            .conditional_enforce_not_equal(&other.bits, condition)
    }
}

impl<ConstraintF: Field> CondSelectGadget<ConstraintF> for Int8<ConstraintF> {
    #[tracing::instrument(target = "r1cs", skip(cond, true_value, false_value))]
    fn conditionally_select(
        cond: &Boolean<ConstraintF>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        let selected_bits = true_value
            .bits
            .iter()
            .zip(&false_value.bits)
            .map(|(t, f)| cond.select(t, f));
        let mut bits = [Boolean::FALSE; 8];
        for (result, new) in bits.iter_mut().zip(selected_bits) {
            *result = new?;
        }

        let value = cond.value().ok().and_then(|cond| {
            if cond {
                true_value.value().ok()
            } else {
                false_value.value().ok()
            }
        });
        Ok(Self { bits, value })
    }
}

impl<F: Field> BitwiseOperationGadget<F> for Int8<F> {
    fn and(&self, other_gadget: &Self) -> anyhow::Result<Self>
    where
        Self: std::marker::Sized,
    {
        let result = zip_bits_and_apply(
            self.to_bits_le()?,
            other_gadget.to_bits_le()?,
            |first_bit, second_bit| first_bit.and(&second_bit),
        )?;
        let new_value = Int8::from_bits_le(&result)?;
        Ok(new_value)
    }

    fn nand(&self, other_gadget: &Self) -> Result<Self>
    where
        Self: std::marker::Sized,
    {
        let result = zip_bits_and_apply(
            self.to_bits_le()?,
            other_gadget.to_bits_le()?,
            |first_bit, second_bit| Ok(first_bit.and(&second_bit)?.not()),
        )?;
        let new_value = Int8::from_bits_le(&result)?;
        Ok(new_value)
    }

    fn nor(&self, other_gadget: &Self) -> Result<Self>
    where
        Self: std::marker::Sized,
    {
        let result = zip_bits_and_apply(
            self.to_bits_le()?,
            other_gadget.to_bits_le()?,
            |first_bit, second_bit| Ok(first_bit.or(&second_bit)?.not()),
        )?;
        let new_value = Int8::from_bits_le(&result)?;
        Ok(new_value)
    }

    fn xor(&self, other_gadget: &Self) -> Result<Self>
    where
        Self: std::marker::Sized,
    {
        let result = zip_bits_and_apply(
            self.to_bits_le()?,
            other_gadget.to_bits_le()?,
            |first_bit, second_bit| first_bit.xor(&second_bit),
        )?;
        let new_value = Int8::from_bits_le(&result)?;
        Ok(new_value)
    }

    fn or(&self, other_gadget: &Self) -> Result<Self>
    where
        Self: std::marker::Sized,
    {
        let result = zip_bits_and_apply(
            self.to_bits_le()?,
            other_gadget.to_bits_le()?,
            |first_bit, second_bit| first_bit.or(&second_bit),
        )?;
        let new_value = Int8::from_bits_le(&result)?;
        Ok(new_value)
    }
}

impl<F: Field> ArithmeticGadget<F> for Int8<F> {
    fn add(&self, addend: &Self) -> Result<Self>
    where
        Self: std::marker::Sized,
    {
        let addend = addend.to_bits_le()?;
        let augend = self.clone().to_bits_le()?;
        let mut sum = vec![Boolean::<F>::FALSE; augend.len()];
        let mut carry = Boolean::<F>::FALSE;
        for (i, (augend_bit, addend_bit)) in augend.iter().zip(addend).enumerate() {
            // Bit by bit sum is an xor for the augend, the addend and the carry bits.
            // carry in | addend | augend | carry out | augend + addend |
            //     0    |    0   |   0    |     0     |        0        |
            //     0    |    0   |   1    |     0     |        1        |
            //     0    |    1   |   0    |     0     |        1        |
            //     0    |    1   |   1    |     1     |        0        |
            //     1    |    0   |   0    |     0     |        1        |
            //     1    |    0   |   1    |     1     |        0        |
            //     1    |    1   |   0    |     1     |        0        |
            //     1    |    1   |   1    |     1     |        1        |
            // sum[i] = (!carry & (augend_bit ^ addend_bit)) | (carry & !(augend_bit ^ addend_bit))
            //        = augend_bit ^ addend_bit ^ carry
            *sum.get_mut(i)
                .ok_or_else(|| anyhow!("Error accessing the index of sum"))? =
                carry.xor(augend_bit)?.xor(&addend_bit)?;
            // To simplify things, the variable carry acts for both the carry in and
            // the carry out.
            // The carry out is augend & addend when the carry in is 0, and it is
            // augend | addend when the carry in is 1.
            // carry = carry.not()
            carry = (carry.not().and(&(augend_bit.and(&addend_bit)?))?)
                .or(&(carry.and(&(augend_bit.or(&addend_bit)?))?))?;
        }
        let result = Self::from_bits_le(&sum)?;
        Ok(result)
    }

    fn sub(&self, subtrahend: &Self) -> Result<Self>
    where
        Self: std::marker::Sized,
    {
        ensure!(
            self.value()?.checked_sub(subtrahend.value()?).is_some(),
            "Subtraction underflow"
        );
        let minuend_as_augend = Self::from_bits_le(
            &(self
                .to_bits_le()?
                .into_iter()
                .map(|bit| bit.not())
                .collect::<Vec<Boolean<F>>>()),
        )?;

        let partial_result = minuend_as_augend.add(subtrahend)?;

        let difference = &partial_result
            .to_bits_le()?
            .into_iter()
            .map(|bit| bit.not())
            .collect::<Vec<Boolean<F>>>();

        let result = Self::from_bits_le(difference)?;
        Ok(result)
    }

    fn mul(&self, multiplicand: &Self, constraint_system: ConstraintSystemRef<F>) -> Result<Self>
    where
        Self: std::marker::Sized,
    {
        let mut product = Self::new_witness(constraint_system.clone(), || Ok(0))?;
        for (i, multiplier_bit) in self.to_bits_le()?.iter().enumerate() {
            // If the multiplier bit is a 1.
            let addend = Self::shift_left(multiplicand, i, constraint_system.clone())?;
            product = Self::conditionally_select(multiplier_bit, &product.add(&addend)?, &product)?;
        }
        Ok(product)
    }

    fn div(&self, divisor: &Self, constraint_system: ConstraintSystemRef<F>) -> Result<Self>
    where
        Self: std::marker::Sized,
    {
        ensure!(divisor.value()? != 0_i8, "attempt to divide by zero");
        let mut quotient = self.clone();
        let mut aux = Self::new_witness(constraint_system.clone(), || Ok(0))?;
        let dividend_sign = self
            .to_bits_be()?
            .get(0)
            .ok_or_else(|| anyhow!("Could not parse dividend bits"))?
            .clone();
        let divisor_sign = divisor
            .to_bits_be()?
            .get(0)
            .ok_or_else(|| anyhow!("Could not parse divisor bits"))?
            .clone();

        let result_sign = divisor_sign.xor(&dividend_sign)?;

        let one = Self::new_constant(constraint_system.clone(), 1)?;

        let dividend_absolute_value = Self::conditionally_select(
            &dividend_sign,
            &helpers::to_absolute_value(self, constraint_system.clone())?,
            self,
        )?;
        let divisor_absolute_value = Self::conditionally_select(
            &divisor_sign,
            &helpers::to_absolute_value(divisor, constraint_system.clone())?,
            divisor,
        )?;

        for dividend_bit in dividend_absolute_value.to_bits_be()? {
            quotient = quotient.shift_left(1, constraint_system.clone())?;
            aux = Self::conditionally_select(
                &dividend_bit,
                &aux.shift_left(1, constraint_system.clone())?.or(&one)?,
                &aux.shift_left(1, constraint_system.clone())?,
            )?;

            let is_greater = divisor_absolute_value.compare(
                &aux,
                Comparison::GreaterThan,
                constraint_system.clone(),
            )?;

            quotient = Self::conditionally_select(&is_greater, &quotient, &quotient.or(&one)?)?;
            aux = if is_greater.value()? {
                aux
            } else {
                aux.sub(&divisor_absolute_value)?
            }
        }

        quotient = Self::conditionally_select(
            &result_sign,
            &helpers::to_two_complement(&quotient, constraint_system)?,
            &quotient,
        )?;
        Ok(quotient)
    }
}

impl<F: Field> ComparisonGadget<F> for Int8<F> {
    fn compare(
        &self,
        gadget_to_compare: &Self,
        comparison: super::Comparison,
        constraint_system: ConstraintSystemRef<F>,
    ) -> Result<Boolean<F>>
    where
        Self: std::marker::Sized,
    {
        helpers::compare_ord(self, gadget_to_compare, comparison, constraint_system)
    }
}

impl<F: Field> BitManipulationGadget<F> for Int8<F> {
    fn rotate_left(
        &self,
        positions: usize,
        constraint_system: ConstraintSystemRef<F>,
    ) -> Result<Self> {
        let primitive_bits = self.to_bits_be()?;
        let mut rotated_bits = primitive_bits.clone();
        rotated_bits.rotate_left(positions);

        for i in 0..8 {
            if let (Some(a), Some(b)) = (
                &primitive_bits.get((i + positions) % 8),
                &rotated_bits.get(i),
            ) {
                let c = lc!() + a.lc() - b.lc();
                constraint_system.enforce_constraint(lc!(), lc!(), c)?
            }
        }

        rotated_bits.reverse();
        Int8::<F>::from_bits_le(&rotated_bits)
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

    fn shift_left(
        &self,
        positions: usize,
        constraint_system: ConstraintSystemRef<F>,
    ) -> Result<Self>
    where
        Self: std::marker::Sized,
    {
        let primitive_bits = self.to_bits_be()?;
        let shifted_value = Int8::<F>::new_witness(constraint_system.clone(), || {
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
        let msb = primitive_bits
            .get(0)
            .ok_or("Could not parse the bits correcly")
            .map_err(|_e| SynthesisError::Unsatisfiable)?;
        let shifted_value = Int8::<F>::new_witness(constraint_system.clone(), || {
            let position_as_u32: u32 = positions
                .try_into()
                .map_err(|_e| SynthesisError::Unsatisfiable)?;
            let (shifted_value, shift_overflowed) = self.value()?.overflowing_shr(position_as_u32);
            if shift_overflowed {
                match msb.value()? {
                    true => Ok(-1_i8),
                    false => Ok(0_i8),
                }
            } else {
                Ok(shifted_value)
            }
        })?;
        let shifted_bits = shifted_value.to_bits_be()?;

        if positions >= 8 {
            // Check that the first positions primitive bits are the same as the msb.
            for c in shifted_bits.iter() {
                constraint_system.enforce_constraint(lc!(), lc!(), c.lc() - msb.lc())?;
            }
        } else {
            // Check that the first positions primitive bits are the same as the msb.
            shifted_bits.iter().take(positions).try_for_each(|c| {
                constraint_system.enforce_constraint(lc!(), lc!(), c.lc() - msb.lc())?;
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
