use ark_crypto_primitives::{
    crh::{TwoToOneCRH, TwoToOneCRHGadget, CRH},
    merkle_tree::{constraints::PathVar, Config, MerkleTree, Path},
};
use ark_r1cs_std::{eq::EqGadget, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use common::*;
pub type Error = Box<dyn ark_std::error::Error>;
pub mod common;

fn main() {}

#[derive(Clone)]
pub struct MerkleConfig;
impl Config for MerkleConfig {
    // Our Merkle tree relies on two hashes: one to hash leaves, and one to hash pairs
    // of internal nodes.
    type LeafHash = LeafHash;
    type TwoToOneHash = TwoToOneHash;
}

/// A Merkle tree containing account information.
pub type SimpleMerkleTree = MerkleTree<MerkleConfig>;
/// The root of the account Merkle tree.
pub type Root = <TwoToOneHash as TwoToOneCRH>::Output;
/// A membership proof for a given account.
pub type SimplePath = Path<MerkleConfig>;
/// The R1CS equivalent of the the Merkle tree root.
pub type RootVar = <TwoToOneHashGadget as TwoToOneCRHGadget<TwoToOneHash, ConstraintF>>::OutputVar;
/// The R1CS equivalent of the the Merkle tree path.
pub type SimplePathVar =
    PathVar<crate::MerkleConfig, LeafHashGadget, TwoToOneHashGadget, ConstraintF>;

#[derive(Clone)]
pub struct MerkleTreeVerification {
    // These are constants that will be embedded into the circuit
    pub leaf_crh_params: <LeafHash as CRH>::Parameters,
    pub two_to_one_crh_params: <TwoToOneHash as TwoToOneCRH>::Parameters,

    // These are the public inputs to the circuit.
    pub root: Root,
    pub leaf: u8,

    // This is the private witness to the circuit.
    pub authentication_path: Option<SimplePath>,
}

impl ConstraintSynthesizer<ConstraintF> for MerkleTreeVerification {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        // First, we allocate the public inputs
        let root = RootVar::new_input(ark_relations::ns!(cs, "root_var"), || Ok(&self.root))?;
        let leaf = UInt8::new_input(ark_relations::ns!(cs, "leaf_var"), || Ok(&self.leaf))?;

        // Then, we allocate the public parameters as constants:
        let leaf_crh_params = LeafHashParamsVar::new_constant(cs.clone(), &self.leaf_crh_params)?;
        let two_to_one_crh_params =
            TwoToOneHashParamsVar::new_constant(cs.clone(), &self.two_to_one_crh_params)?;

        // Finally, we allocate our path as a private witness variable:
        let path = SimplePathVar::new_witness(ark_relations::ns!(cs, "path_var"), || {
            Ok(self.authentication_path.as_ref().unwrap())
        })?;

        let leaf_bytes = vec![leaf; 1];

        // Now, we have to check membership. How do we do that?
        // Hint: look at https://github.com/arkworks-rs/crypto-primitives/blob/6be606259eab0aec010015e2cfd45e4f134cd9bf/src/merkle_tree/constraints.rs#L135

        let is_member = path.verify_membership(
            &leaf_crh_params,
            &two_to_one_crh_params,
            &root,
            &leaf_bytes.as_slice(),
        )?;

        is_member.enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{LeafHash, MerkleTreeVerification, TwoToOneCRH, TwoToOneHash, CRH};
    use ark_bls12_377::{Bls12_377, Fr};
    use ark_marlin::{Marlin, SimpleHashFiatShamirRng};
    use ark_poly::univariate::DensePolynomial;
    use ark_poly_commit::marlin_pc::MarlinKZG10;
    use ark_relations::r1cs::{ConstraintLayer, ConstraintSynthesizer, ConstraintSystem};
    use blake2::Blake2s;
    use rand_chacha::ChaChaRng;

    type MultiPC = MarlinKZG10<Bls12_377, DensePolynomial<Fr>>;
    type FS = SimpleHashFiatShamirRng<Blake2s, ChaChaRng>;
    type MarlinInst = Marlin<Fr, MultiPC, FS>;

    // Run this test via `cargo test --release test_merkle_tree`.
    #[test]
    fn merkle_tree_constraints_correctness() {
        // Let's set up an RNG for use within tests. Note that this is *not* safe
        // for any production use.
        let mut rng = ark_std::test_rng();

        // First, let's sample the public parameters for the hash functions:
        let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
        let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

        // Next, let's construct our tree.
        // This follows the API in https://github.com/arkworks-rs/crypto-primitives/blob/6be606259eab0aec010015e2cfd45e4f134cd9bf/src/merkle_tree/mod.rs#L156
        let tree = crate::SimpleMerkleTree::new(
            &leaf_crh_params,
            &two_to_one_crh_params,
            &[1u8, 2u8, 3u8, 10u8, 9u8, 17u8, 70u8, 45u8], // the i-th entry is the i-th leaf.
        )
        .unwrap();

        // Now, let's try to generate a membership proof for the 5th item, i.e. 9.
        let proof = tree.generate_proof(4).unwrap(); // we're 0-indexing!
                                                     // This should be a proof for the membership of a leaf with value 9. Let's check that!

        // First, let's get the root we want to verify against:
        let root = tree.root();

        let circuit = MerkleTreeVerification {
            // constants
            leaf_crh_params,
            two_to_one_crh_params,

            // public inputs
            root,
            leaf: 9u8,

            // witness
            authentication_path: Some(proof),
        };

        // Next, let's make the circuit!
        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        // Let's check whether the constraint system is satisfied
        let is_satisfied = cs.is_satisfied().unwrap();
        if !is_satisfied {
            // If it isn't, find out the offending constraint.
            println!("{:?}", cs.which_is_unsatisfied());
        }
        assert!(is_satisfied);
    }

    // Run this test via `cargo test --release test_merkle_tree_constraints_soundness`.
    // This tests that a given invalid authentication path will fail.
    #[test]
    fn merkle_tree_constraints_soundness() {
        // Let's set up an RNG for use within tests. Note that this is *not* safe
        // for any production use.
        let mut rng = ark_std::test_rng();

        // First, let's sample the public parameters for the hash functions:
        let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
        let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

        // Next, let's construct our tree.
        // This follows the API in https://github.com/arkworks-rs/crypto-primitives/blob/6be606259eab0aec010015e2cfd45e4f134cd9bf/src/merkle_tree/mod.rs#L156
        let tree = crate::SimpleMerkleTree::new(
            &leaf_crh_params,
            &two_to_one_crh_params,
            &[1u8, 2u8, 3u8, 10u8, 9u8, 17u8, 70u8, 45u8], // the i-th entry is the i-th leaf.
        )
        .unwrap();

        // We just mutate the first leaf
        let second_tree = crate::SimpleMerkleTree::new(
            &leaf_crh_params,
            &two_to_one_crh_params,
            &[4u8, 2u8, 3u8, 10u8, 9u8, 17u8, 70u8, 45u8], // the i-th entry is the i-th leaf.
        )
        .unwrap();

        // Now, let's try to generate a membership proof for the 5th item, i.e. 9.
        let proof = tree.generate_proof(4).unwrap(); // we're 0-indexing!

        // But, let's get the root we want to verify against:
        let wrong_root = second_tree.root();

        let circuit = MerkleTreeVerification {
            // constants
            leaf_crh_params,
            two_to_one_crh_params,

            // public inputs
            root: wrong_root,
            leaf: 9u8,

            // witness
            authentication_path: Some(proof),
        };

        // Next, let's make the constraint system!
        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        // Let's check whether the constraint system is satisfied
        let is_satisfied = cs.is_satisfied().unwrap();
        // We expect this to fail!
        assert!(!is_satisfied);
    }

    #[test]
    fn merkle_tree_test_proof() {
        let mut rng = ark_std::test_rng();
        let universal_srs = MarlinInst::universal_setup(100000, 25000, 300000, &mut rng).unwrap();

        // First, let's sample the public parameters for the hash functions:
        let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
        let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

        // Next, let's construct our tree.
        // This follows the API in https://github.com/arkworks-rs/crypto-primitives/blob/6be606259eab0aec010015e2cfd45e4f134cd9bf/src/merkle_tree/mod.rs#L156
        let tree = crate::SimpleMerkleTree::new(
            &leaf_crh_params,
            &two_to_one_crh_params,
            &[1u8, 2u8, 3u8, 10u8, 9u8, 17u8, 70u8, 45u8], // the i-th entry is the i-th leaf.
        )
        .unwrap();

        // Now, let's try to generate a membership proof for the 5th item, i.e. 9.
        // This should be a proof for the membership of a leaf with value 9. Let's check that!
        let proof = tree.generate_proof(4).unwrap();

        // First, let's get the root we want to verify against:
        let root = tree.root();

        let circuit = MerkleTreeVerification {
            // constants
            leaf_crh_params,
            two_to_one_crh_params,

            // public inputs
            root,
            leaf: 9u8,

            // witness
            authentication_path: Some(proof),
        };

        // Now, try to generate the verifying key and proving key with Marlin
        let (index_pk, index_vk) = MarlinInst::index(&universal_srs, circuit.clone()).unwrap();

        // generate the proof
        let proof = MarlinInst::prove(&index_pk, circuit.clone(), &mut rng).unwrap();

        // check the proof
        let one = Fr::from(1);
        let zero = Fr::from(0);
        let inputs = vec![root, one, zero, zero, one, zero, zero, zero, zero];
        assert!(MarlinInst::verify(&index_vk, &inputs, &proof, &mut rng).unwrap());
    }
}
