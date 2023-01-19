use super::common::{ConstraintF, LeafHash, LeafHashGadget, TwoToOneHash, TwoToOneHashGadget};
use super::merkle_tree::MerkleConfig;
use crate::marlin::MarlinInst;
use crate::marlin::MultiPC;
use crate::merkle_tree::merkle_tree_verification_u8::MerkleTreeVerificationU8;
use anyhow::{anyhow, Result};
use ark_bls12_377::Fr;
use ark_crypto_primitives::{
    crh::{TwoToOneCRH, CRH},
    merkle_tree::{constraints::PathVar, MerkleTree, Path},
};
use ark_ff::ToBytes;
use ark_marlin::Proof;
use ark_marlin::{IndexProverKey, IndexVerifierKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bitvec::array::BitArray;

/// A membership proof for a given account.
pub type SimplePath = Path<MerkleConfig>;

/// The R1CS equivalent of the the Merkle tree path.
pub type SimplePathVar = PathVar<MerkleConfig, LeafHashGadget, TwoToOneHashGadget, ConstraintF>;

/// A Merkle tree of fixed size containing account information.
pub struct SimpleMerkleTree {
    pub tree: MerkleTree<MerkleConfig>,
    pub leaf_crh_params: <LeafHash as CRH>::Parameters,
    pub two_to_one_crh_params: <TwoToOneHash as TwoToOneCRH>::Parameters,
    pub proving_key: IndexProverKey<Fr, MultiPC>,
    pub verifying_key: IndexVerifierKey<Fr, MultiPC>,
}

impl SimpleMerkleTree {
    pub fn new<L: ToBytes>(leaves: &[L]) -> Result<Self> {
        // Let's set up an RNG for use within tests.
        // Note that this is *not* safe for any production use.
        let mut rng = ark_std::test_rng();
        let universal_srs = MarlinInst::universal_setup(100_000, 25_000, 300_000, &mut rng)
            .map_err(|e| anyhow!("{:?}", e))?;

        // First, let's sample the public parameters for the hash functions:
        let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).map_err(|e| anyhow!("{}", e))?;
        let two_to_one_crh_params =
            <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).map_err(|e| anyhow!("{}", e))?;

        let tree =
            MerkleTree::<MerkleConfig>::new(&leaf_crh_params, &two_to_one_crh_params, leaves)
                .map_err(|e| anyhow!("{}", e))?;

        /*
            IMPORTANT:
            We are creating an empty merkle tree here just to be able to derive the proving and
            verifying keys for it, so we can store and use them later whenever we need to
            prove/verify. This merkle tree circuit works for fixed tree heights, so different
            heights will result in a different amount of constraints, and thus different proving and
            verifying keys.
        */
        let blank_tree: MerkleTree<MerkleConfig> = MerkleTree::blank(
            &leaf_crh_params,
            &two_to_one_crh_params,
            merkle_tree_height(leaves.len()),
        )
        .map_err(|e| anyhow!("{}", e))?;

        let blank_merkle_path = blank_tree.generate_proof(0).map_err(|e| anyhow!("{}", e))?;

        let dummy_circuit = MerkleTreeVerificationU8 {
            // constants
            leaf_crh_params: leaf_crh_params.clone(),
            two_to_one_crh_params: two_to_one_crh_params.clone(),

            // public inputs
            root: blank_tree.root(),
            leaf: 0,

            // witness
            authentication_path: Some(blank_merkle_path),
        };

        // Now, try to generate the verifying key and proving key with Marlin
        let (proving_key, verifying_key) =
            MarlinInst::index(&universal_srs, dummy_circuit).map_err(|e| anyhow!("{:?}", e))?;

        Ok(Self {
            tree,
            leaf_crh_params,
            two_to_one_crh_params,
            proving_key,
            verifying_key,
        })
    }

    pub fn get_merkle_path(&self, leaf_index: usize) -> Result<Path<MerkleConfig>> {
        let path = self
            .tree
            .generate_proof(leaf_index)
            .map_err(|e| anyhow!("{:?}", e))?;
        Ok(path)
    }

    pub fn prove(&self, leaf: u8, merkle_path: SimplePath) -> Result<Vec<u8>> {
        let circuit = MerkleTreeVerificationU8 {
            // constants
            leaf_crh_params: self.leaf_crh_params.clone(),
            two_to_one_crh_params: self.two_to_one_crh_params.clone(),

            // public inputs
            root: self.tree.root(),
            leaf,

            // witness
            authentication_path: Some(merkle_path),
        };

        // generate the proof
        let mut rng = ark_std::test_rng();

        let proof = MarlinInst::prove(&self.proving_key, circuit, &mut rng)
            .map_err(|e| anyhow!("{:?}", e))?;

        let mut bytes = Vec::new();
        proof
            .serialize(&mut bytes)
            .map_err(|e| anyhow!("{:?}", e))?;
        Ok(bytes)
    }

    pub fn verify(&self, proof: &[u8], input: u8) -> Result<bool> {
        let one = Fr::from(1_i32);
        let zero = Fr::from(0_i32);
        let root = self.tree.root();
        let mut input_vec = vec![root];

        let bits = BitArray::<u8>::from(input);

        for bit in bits.iter().by_vals() {
            if bit {
                input_vec.push(one)
            } else {
                input_vec.push(zero)
            }
        }

        let proof = Proof::<Fr, MultiPC>::deserialize(proof).map_err(|e| anyhow!("{:?}", e))?;
        let mut rng = ark_std::test_rng();

        let result = MarlinInst::verify(&self.verifying_key, &input_vec, &proof, &mut rng)
            .map_err(|e| anyhow!("{:?}", e))?;

        Ok(result)
    }
}

fn merkle_tree_height(mut leaves_length: usize) -> usize {
    let mut result = 0;
    while leaves_length != 0 {
        result += 1;
        leaves_length >>= 1_i32;
    }

    result
}

pub fn check_leave_exists_u8<L: ToBytes>(
    tree: &SimpleMerkleTree,
    leaf: u8,
    path: Path<MerkleConfig>,
) -> Result<bool> {
    // get the root
    let root = tree.tree.root();
    let mut rng = ark_std::test_rng();
    let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).map_err(|e| anyhow!("{}", e))?;
    let two_to_one_crh_params =
        <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).map_err(|e| anyhow!("{}", e))?;

    let circuit = MerkleTreeVerificationU8 {
        // constants
        leaf_crh_params,
        two_to_one_crh_params,

        // public inputs
        root,
        leaf,

        // witness
        authentication_path: Some(path),
    };

    // make the circuit
    let cs = ConstraintSystem::new_ref();
    circuit
        .generate_constraints(cs.clone())
        .map_err(|_e| anyhow!("Error generating constrinaints"))?;

    // check whether the constraint system is satisfied
    let is_satisfied = cs
        .is_satisfied()
        .map_err(|_e| anyhow!("Error checking if the constrinaints are satisfied"))?;

    Ok(is_satisfied)
}

#[cfg(test)]
mod tests {
    use super::super::common::{LeafHash, TwoToOneHash};
    use ark_crypto_primitives::crh::{TwoToOneCRH, CRH};
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use bitvec::array::BitArray;

    #[allow(clippy::print_stdout)]
    #[test]
    fn bit_test() {
        let bits = BitArray::<u8>::from(254);

        for bit in bits.iter().by_vals() {
            match bit {
                false => println!("0"),
                true => println!("1"),
            }
        }
    }

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
        // the i-th entry is the i-th leaf.
        let tree =
            super::SimpleMerkleTree::new(&[1_u8, 2_u8, 3_u8, 10_u8, 9_u8, 17_u8, 70_u8, 45_u8])
                .unwrap();

        // We just mutate the first leaf
        // the i-th entry is the i-th leaf.
        let second_tree =
            super::SimpleMerkleTree::new(&[4_u8, 2_u8, 3_u8, 10_u8, 9_u8, 17_u8, 70_u8, 45_u8])
                .unwrap();

        // Now, let's try to generate a membership proof for the 5th item, i.e. 9.
        let proof = tree.tree.generate_proof(4).unwrap(); // we're 0-indexing!

        // But, let's get the root we want to verify against:
        let wrong_root = second_tree.tree.root();

        let circuit = super::MerkleTreeVerificationU8 {
            // constants
            leaf_crh_params,
            two_to_one_crh_params,

            // public inputs
            root: wrong_root,
            leaf: 9_u8,

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
        // Next, let's construct our tree.
        // This follows the API in https://github.com/arkworks-rs/crypto-primitives/blob/6be606259eab0aec010015e2cfd45e4f134cd9bf/src/merkle_tree/mod.rs#L156
        // the i-th entry is the i-th leaf.
        let tree =
            super::SimpleMerkleTree::new(&[1_u8, 2_u8, 3_u8, 10_u8, 9_u8, 17_u8, 70_u8, 45_u8])
                .unwrap();

        let merkle_path = tree.tree.generate_proof(4).unwrap();

        // Now, try to generate the verifying key and proving key with Marlin
        let proof = tree.prove(9_u8, merkle_path).unwrap();

        let verify_ret = tree.verify(&proof, 9_u8).unwrap();

        assert!(verify_ret);
    }
}
