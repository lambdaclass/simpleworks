use super::common::{ConstraintF, LeafHash, TwoToOneHash, TwoToOneHashGadget};
use ark_crypto_primitives::{
    crh::{TwoToOneCRH, TwoToOneCRHGadget},
    merkle_tree::Config,
};

pub type Error = Box<dyn ark_std::error::Error>;

#[derive(Clone)]
pub struct MerkleConfig;

impl Config for MerkleConfig {
    // Our Merkle tree relies on two hashes:
    // one to hash leaves,
    // and one to hash pairs of internal nodes.
    type LeafHash = LeafHash;
    type TwoToOneHash = TwoToOneHash;
}

/// The root of the account Merkle tree.
pub type Root = <TwoToOneHash as TwoToOneCRH>::Output;

/// The R1CS equivalent of the the Merkle tree root.
pub type RootVar = <TwoToOneHashGadget as TwoToOneCRHGadget<TwoToOneHash, ConstraintF>>::OutputVar;
