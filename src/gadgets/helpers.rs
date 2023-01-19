use anyhow::Result;
use ark_ff::Field;
use ark_r1cs_std::prelude::Boolean;
use ark_relations::r1cs::SynthesisError;

pub fn zip_bits_and_apply<F: Field, T>(
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
