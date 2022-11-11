use super::common::{ConstraintF, LeafHash, LeafHashGadget, TwoToOneHash, TwoToOneHashGadget};
use super::merkle_tree::MerkleConfig;
use crate::marlin::MarlinInst;
use crate::marlin::MultiPC;
use crate::merkle_tree::merkle_tree_verification_u8::MerkleTreeVerificationU8;
use anyhow::{anyhow, Result};
use ark_bls12_381::Fr;
use ark_crypto_primitives::{
    crh::{TwoToOneCRH, CRH},
    merkle_tree::{constraints::PathVar, MerkleTree, Path},
};
use ark_ff::ToBytes;
use ark_marlin::Proof;
use ark_marlin::{IndexProverKey, IndexVerifierKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bitvec::array::BitArray;

/// A Merkle tree containing account information.
pub struct SimpleMerkleTree {
    pub tree: MerkleTree<MerkleConfig>,
    pub leaf_crh_params: <LeafHash as CRH>::Parameters,
    pub two_to_one_crh_params: <TwoToOneHash as TwoToOneCRH>::Parameters,
    pub proving_key: IndexProverKey<Fr, MultiPC>,
    pub verifying_key: IndexVerifierKey<Fr, MultiPC>,
}

/// A membership proof for a given account.
pub type SimplePath = Path<MerkleConfig>;

/// The R1CS equivalent of the the Merkle tree path.
pub type SimplePathVar = PathVar<MerkleConfig, LeafHashGadget, TwoToOneHashGadget, ConstraintF>;

impl SimpleMerkleTree {
    pub fn new_simple_merkle_tree<L: ToBytes>(leaves: &[L]) -> Result<Self> {
        // Let's set up an RNG for use within tests.
        // Note that this is *not* safe for any production use.
        let mut rng = ark_std::test_rng();
        let universal_srs = MarlinInst::universal_setup(100000, 25000, 300000, &mut rng)
            .map_err(|_e| anyhow!("Error in universal setup"))?;

        // First, let's sample the public parameters for the hash functions:
        let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).map_err(|e| anyhow!("{}", e))?;
        let two_to_one_crh_params =
            <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).map_err(|e| anyhow!("{}", e))?;

        let tree =
            MerkleTree::<MerkleConfig>::new(&leaf_crh_params, &two_to_one_crh_params, leaves)
                .map_err(|e| anyhow!("{}", e))?;

        let blank_tree: MerkleTree<MerkleConfig> =
            MerkleTree::blank(&leaf_crh_params, &two_to_one_crh_params, 1)
                .map_err(|e| anyhow!("{}", e))?;

        let dummy_circuit = MerkleTreeVerificationU8 {
            // constants
            leaf_crh_params: leaf_crh_params.clone(),
            two_to_one_crh_params: two_to_one_crh_params.clone(),

            // public inputs
            root: blank_tree.root(),
            leaf: 0,

            // witness
            authentication_path: None,
        };

        // Now, try to generate the verifying key and proving key with Marlin
        let (proving_key, verifying_key) = MarlinInst::index(&universal_srs, dummy_circuit)
            .map_err(|_e| anyhow!("Error in Marlin Inst"))?;

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
            .map_err(|_e| anyhow!("Error generating merkle path"))?;
        Ok(path)
    }
}

impl SimpleMerkleTree {
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
            .map_err(|_e| anyhow!("Error generating proof"))?;

        let mut bytes = Vec::new();
        proof
            .serialize(&mut bytes)
            .map_err(|_e| anyhow!("Error serializing proof"))?;
        Ok(bytes)
    }

    pub fn verify(&self, proof: &[u8], input: u8) -> Result<bool> {
        let one = Fr::from(1_i32);
        let zero = Fr::from(0_i32);
        let root = self.tree.root();
        let mut input_vec = vec![root];

        let bits = BitArray::<u8>::from(input);

        for bit in bits.iter().by_vals() {
            match bit {
                false => input_vec.push(zero),
                true => input_vec.push(one),
            }
        }

        let proof = Proof::<Fr, MultiPC>::deserialize(proof)
            .map_err(|_e| anyhow!("Error Deserializing proof"))?;
        let mut rng = ark_std::test_rng();

        let result = MarlinInst::verify(&self.verifying_key, &input_vec, &proof, &mut rng)
            .map_err(|_e| anyhow!("Error verifying proof"))?;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use bitvec::array::BitArray;

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
}
