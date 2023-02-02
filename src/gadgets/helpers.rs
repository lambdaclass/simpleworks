use anyhow::{anyhow, Result};
use ark_ff::Field;
use ark_r1cs_std::ToBitsGadget;
use ark_r1cs_std::{
    prelude::{AllocVar, Boolean},
    select::CondSelectGadget,
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use super::{int8::Int8, traits::ArithmeticGadget};

pub enum Comparison {
    GreaterThan,
    GreaterThanOrEqual,
    LessThanOrEqual,
    LessThan,
}

impl Comparison {
    pub fn instruction(&self) -> &str {
        match self {
            Comparison::GreaterThan => "gt",
            Comparison::GreaterThanOrEqual => "gte",
            Comparison::LessThanOrEqual => "lte",
            Comparison::LessThan => "lt",
        }
    }
}

pub(crate) fn zip_bits_and_apply<F: Field, T>(
    first_bits_to_iterate: Vec<Boolean<F>>,
    second_bits_to_iterate: Vec<Boolean<F>>,
    function_to_apply: T,
) -> Result<Vec<Boolean<F>>>
where
    T: Fn(Boolean<F>, Boolean<F>) -> Result<Boolean<F>, SynthesisError>,
{
    let mut result = Vec::new();
    for (left_operand_bit, right_operand_bit) in first_bits_to_iterate
        .iter()
        .zip(second_bits_to_iterate.iter())
    {
        let operation_result =
            function_to_apply(left_operand_bit.clone(), right_operand_bit.clone())?;
        result.push(operation_result);
    }
    Ok(result)
}

pub(crate) fn compare_ord<F: Field, T: R1CSVar<F>>(
    left_operand: T,
    right_operand: T,
    comparison: Comparison,
    constraint_system: ConstraintSystemRef<F>,
) -> Result<Boolean<F>>
where
    T::Value: PartialOrd,
{
    let result = match comparison {
        Comparison::GreaterThan => left_operand.value()? > right_operand.value()?,
        Comparison::GreaterThanOrEqual => left_operand.value()? >= right_operand.value()?,
        Comparison::LessThanOrEqual => left_operand.value()? <= right_operand.value()?,
        Comparison::LessThan => left_operand.value()? < right_operand.value()?,
    };

    let true_witness = Boolean::<F>::new_witness(constraint_system.clone(), || Ok(true))?;
    let false_witness = Boolean::<F>::new_witness(constraint_system.clone(), || Ok(false))?;

    Boolean::conditionally_select(
        &Boolean::new_witness(constraint_system, || Ok(result))?,
        &true_witness,
        &false_witness,
    )
    .map_err(|error| anyhow!(error))
}

pub(crate) fn to_absolute_value<F>(
    negative_number: &Int8<F>,
    constraint_system: ConstraintSystemRef<F>,
) -> Result<Int8<F>>
where
    F: Field,
{
    let one = Int8::new_constant(constraint_system, 1)?;
    let a = negative_number.sub(&one)?;
    let a = a
        .to_bits_le()?
        .into_iter()
        .map(|bit| bit.not())
        .collect::<Vec<Boolean<F>>>();

    Int8::from_bits_le(&a)
}

pub(crate) fn to_two_complement<F>(
    positive_number: &Int8<F>,
    constraint_system: ConstraintSystemRef<F>,
) -> Result<Int8<F>>
where
    F: Field,
{
    let one = Int8::new_constant(constraint_system, 1)?;
    let a = positive_number
        .to_bits_le()?
        .into_iter()
        .map(|bit| bit.not())
        .collect::<Vec<Boolean<F>>>();
    let a = Int8::from_bits_le(&a)?;
    a.add(&one)
}
