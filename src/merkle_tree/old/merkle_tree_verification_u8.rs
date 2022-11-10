use super::common::{
    ConstraintF, LeafHash, LeafHashParamsVar, TwoToOneHash, TwoToOneHashParamsVar,
};
use super::merkle_tree::{Root, RootVar};
use super::simple_merkle_tree::{SimplePath, SimplePathVar};
use anyhow::Result;
use ark_crypto_primitives::crh::{TwoToOneCRH, CRH};
use ark_r1cs_std::{eq::EqGadget, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

#[derive(Clone)]
pub struct MerkleTreeVerificationU8 {
    // These are constants that will be embedded into the circuit
    pub leaf_crh_params: <LeafHash as CRH>::Parameters,
    pub two_to_one_crh_params: <TwoToOneHash as TwoToOneCRH>::Parameters,

    // These are the public inputs to the circuit.
    pub root: Root,
    pub leaf: u8,

    // This is the private witness to the circuit.
    pub authentication_path: Option<SimplePath>,
}

impl ConstraintSynthesizer<ConstraintF> for MerkleTreeVerificationU8 {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        // public inputs
        let root = RootVar::new_input(ark_relations::ns!(cs, "root_var"), || Ok(&self.root))?;
        let leaf = UInt8::new_input(ark_relations::ns!(cs, "leaf_var"), || Ok(&self.leaf))?;

        // public parameters as constants:
        let leaf_crh_params = LeafHashParamsVar::new_constant(cs.clone(), &self.leaf_crh_params)?;
        let two_to_one_crh_params =
            TwoToOneHashParamsVar::new_constant(cs.clone(), &self.two_to_one_crh_params)?;

        // the path is a private witness variable:
        let authentication_path = self
            .authentication_path
            .as_ref()
            .ok_or(SynthesisError::MissingCS)?;
        let path = SimplePathVar::new_witness(ark_relations::ns!(cs, "path_var"), || {
            Ok(authentication_path)
        })?;

        // check membership of the leaf in the tree
        let leaf_bytes = vec![leaf; 1];
        let is_member = path.verify_membership(
            &leaf_crh_params,
            &two_to_one_crh_params,
            &root,
            &leaf_bytes.as_slice(),
        )?;
        is_member.enforce_equal(&Boolean::TRUE)
    }
}
