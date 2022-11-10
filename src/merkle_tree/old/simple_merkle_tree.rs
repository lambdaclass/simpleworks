use super::common::{ConstraintF, LeafHash, LeafHashGadget, TwoToOneHash, TwoToOneHashGadget};
use super::merkle_tree::MerkleConfig;
use anyhow::{anyhow, Result};
use ark_crypto_primitives::{
    crh::{TwoToOneCRH, CRH},
    merkle_tree::{constraints::PathVar, MerkleTree, Path},
};
use ark_ff::ToBytes;

/// A Merkle tree containing account information.
pub type SimpleMerkleTree = MerkleTree<MerkleConfig>;

/// A membership proof for a given account.
pub type SimplePath = Path<MerkleConfig>;

/// The R1CS equivalent of the the Merkle tree path.
pub type SimplePathVar = PathVar<MerkleConfig, LeafHashGadget, TwoToOneHashGadget, ConstraintF>;

pub fn new_simple_merkle_tree_from_rng<L: ToBytes>(leaves: &[L]) -> Result<SimpleMerkleTree> {
    // Let's set up an RNG for use within tests. Note that this is *not* safe
    // for any production use.
    let mut rng = ark_std::test_rng();

    // First, let's sample the public parameters for the hash functions:
    let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).map_err(|e| anyhow!("{}", e))?;
    let two_to_one_crh_params =
        <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).map_err(|e| anyhow!("{}", e))?;

    SimpleMerkleTree::new(&leaf_crh_params, &two_to_one_crh_params, leaves)
        .map_err(|e| anyhow!("{}", e))
}
