use anyhow::{anyhow, Result};
use ark_bls12_381::{Bls12_381, Fr};
use ark_marlin::{Marlin, SimpleHashFiatShamirRng};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::marlin_pc::MarlinKZG10;
use ark_serialize::CanonicalSerialize;
use blake2::Blake2s;
use rand::rngs::StdRng;
use rand_chacha::ChaChaRng;

pub type MultiPC = MarlinKZG10<Bls12_381, DensePolynomial<Fr>>;
pub type FS = SimpleHashFiatShamirRng<Blake2s, ChaChaRng>;
pub type MarlinInst = Marlin<Fr, MultiPC, FS>;
pub type UniversalSRS = ark_marlin::UniversalSRS<Fr, MultiPC>;
pub type ConstraintSystemRef = ark_relations::r1cs::ConstraintSystemRef<Fr>;

pub fn generate_rand() -> StdRng {
    ark_std::test_rng()
}

pub fn generate_universar_srs(rng: &mut StdRng) -> Result<UniversalSRS> {
    MarlinInst::universal_setup(100000, 25000, 300000, rng)
        .map_err(|_e| anyhow!("Error generating universal srs"))
}

pub fn generate_proof(
    universal_srs: &UniversalSRS,
    rng: &mut StdRng,
    constraint_system: ConstraintSystemRef,
) -> Result<(Vec<u8>, Vec<u8>)> {
    // Try to generate the verifying key and proving key with Marlin
    let (index_proving_key, index_verifying_key) =
        MarlinInst::index_from_constraint_system(universal_srs, constraint_system.clone())
            .map_err(|_e| anyhow!("Error in index_from_constraint_system"))?;

    let proof =
        MarlinInst::prove_from_constraint_system(&index_proving_key, constraint_system, rng)
            .map_err(|_e| anyhow!("Error in prove_from_constraint_system"))?;

    let mut bytes_proof = Vec::new();
    proof
        .serialize(&mut bytes_proof)
        .map_err(|_e| anyhow!("Error serializing proof"))?;

    let mut bytes_verifying_key = Vec::new();
    index_verifying_key
        .serialize(&mut bytes_verifying_key)
        .map_err(|_e| anyhow!("Error serializing verifying_key"))?;

    Ok((bytes_verifying_key, bytes_proof))
}
