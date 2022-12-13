use ark_crypto_primitives::crh::{injective_map::{PedersenCRHCompressor, TECompressor},};
use ark_ed_on_bls12_381::EdwardsProjective;
use ark_crypto_primitives::crh::{pedersen};

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct LeafWindow;

impl pedersen::Window for LeafWindow {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 144;
}

pub type PedersenHash = PedersenCRHCompressor<EdwardsProjective, TECompressor, LeafWindow>;
