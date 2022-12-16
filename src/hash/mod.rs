use anyhow::{anyhow, Result};
use ark_crypto_primitives::crh::pedersen;
use ark_crypto_primitives::{
    crh::injective_map::{PedersenCRHCompressor, TECompressor},
    CRH,
};
use ark_ed_on_bls12_377::{EdwardsProjective, Fq};

#[derive(Clone, PartialEq, Eq, Hash)]
struct LeafWindow;

impl pedersen::Window for LeafWindow {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 144;
}

type PedersenHash = PedersenCRHCompressor<EdwardsProjective, TECompressor, LeafWindow>;

pub fn pedersen_hash(input: &[u8]) -> Result<Fq> {
    let mut rng = ark_std::test_rng();
    let params = PedersenHash::setup(&mut rng).map_err(|e| anyhow!("{:?}", e))?;

    PedersenHash::evaluate(&params, input).map_err(|e| anyhow!("{:?}", e))
}
