use anyhow::{anyhow, Result};
use ark_crypto_primitives::crh::pedersen;
use ark_crypto_primitives::{
    crh::injective_map::{PedersenCRHCompressor, TECompressor},
    CRH,
};
use ark_ed_on_bls12_377::{EdwardsProjective, Fq};
use ark_sponge::poseidon::PoseidonSponge;
use ark_sponge::{CryptographicSponge, FieldBasedCryptographicSponge};

pub mod helpers;

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

type PoseidonHash = PoseidonSponge<Fq>;

pub fn poseidon2_hash(input: &[u8]) -> Result<Fq> {
    let sponge_params = helpers::poseidon_parameters_for_test()?;

    let mut native_sponge = PoseidonHash::new(&sponge_params);

    native_sponge.absorb(&input);
    native_sponge
        .squeeze_native_field_elements(1)
        .first()
        .ok_or_else(|| anyhow!("Error getting the first element of the input"))
        .copied()
}
