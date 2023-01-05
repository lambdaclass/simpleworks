use super::ConstraintF;
use crate::hash;
use anyhow::{anyhow, Result};
use ark_r1cs_std::{fields::fp::FpVar, R1CSVar};
use ark_sponge::{
    constraints::{AbsorbGadget, CryptographicSpongeVar},
    poseidon::constraints::PoseidonSpongeVar,
};

type PoseidonGadget = PoseidonSpongeVar<ConstraintF>;

pub fn poseidon2_hash(input: &impl AbsorbGadget<ConstraintF>) -> Result<FpVar<ConstraintF>> {
    let input_bytes = input.to_sponge_bytes()?;

    let cs = input_bytes
        .first()
        .ok_or_else(|| anyhow!("Error getting the first element of the input"))?
        .cs();

    let sponge_params = hash::helpers::poseidon_parameters_for_test()?;

    let mut constraint_sponge = PoseidonGadget::new(cs, &sponge_params);

    constraint_sponge.absorb(&input)?;
    constraint_sponge
        .squeeze_field_elements(1)
        .map_err(|e| anyhow!(e.to_string()))?
        .first()
        .ok_or_else(|| anyhow!("Error getting the first element of the input"))
        .cloned()
}

#[cfg(test)]
mod tests {
    use crate::{
        gadgets::{self, UInt8Gadget},
        hash,
    };
    use ark_r1cs_std::R1CSVar;
    use ark_relations::{ns, r1cs::ConstraintSystem};

    #[test]
    fn test_poseidon2_hash_primitive_and_gadget_implementations_comparison() {
        let cs = ConstraintSystem::new_ref();

        let message = b"Hello World";
        let message_var = UInt8Gadget::new_input_vec(ns!(cs, "input"), message).unwrap();

        let primitive_squeeze = hash::poseidon2_hash(message).unwrap();
        let squeeze_var = gadgets::poseidon2_hash(&message_var).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(squeeze_var.value().unwrap(), primitive_squeeze);
    }
}
