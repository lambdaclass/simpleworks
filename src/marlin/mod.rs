use anyhow::{anyhow, Result};
use ark_bls12_381::{Bls12_381, Fr, FrParameters, Parameters};
use ark_ec::bls12::Bls12;
use ark_ff::Fp256;
use ark_marlin::{IndexProverKey, IndexVerifierKey, Marlin, Proof, SimpleHashFiatShamirRng};
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
pub type VerifyingKey = IndexVerifierKey<
    Fp256<FrParameters>,
    MarlinKZG10<Bls12<Parameters>, DensePolynomial<Fp256<FrParameters>>>,
>;
pub type ProvingKey = IndexProverKey<
    Fp256<FrParameters>,
    MarlinKZG10<Bls12<Parameters>, DensePolynomial<Fp256<FrParameters>>>,
>;
pub type MarlinProof =
    Proof<Fr, MarlinKZG10<Bls12<Parameters>, DensePolynomial<Fp256<FrParameters>>>>;
use ark_serialize::CanonicalDeserialize;

use crate::types::value::SimpleworksValueType;

pub fn generate_rand() -> StdRng {
    ark_std::test_rng()
}

pub fn generate_universal_srs(rng: &mut StdRng) -> Result<UniversalSRS> {
    MarlinInst::universal_setup(100000, 25000, 300000, rng)
        .map_err(|_e| anyhow!("Error generating universal srs"))
}

pub fn generate_proof(
    universal_srs: &UniversalSRS,
    rng: &mut StdRng,
    constraint_system: ConstraintSystemRef,
) -> Result<Vec<u8>> {
    // Try to generate the verifying key and proving key with Marlin
    let (index_proving_key, _index_verifying_key) =
        MarlinInst::index_from_constraint_system(universal_srs, constraint_system.clone())
            .map_err(|_e| anyhow!("Error in index_from_constraint_system"))?;

    let proof =
        MarlinInst::prove_from_constraint_system(&index_proving_key, constraint_system, rng)
            .map_err(|_e| anyhow!("Error in prove_from_constraint_system"))?;

    let mut bytes_proof = Vec::new();
    proof
        .serialize(&mut bytes_proof)
        .map_err(|_e| anyhow!("Error serializing proof"))?;

    Ok(bytes_proof)
}

pub fn verify_proof(
    verifying_key_serialized: Vec<u8>,
    public_inputs: &[SimpleworksValueType],
    proof_serialized: Vec<u8>,
) -> Result<bool> {
    let verifying_key = VerifyingKey::deserialize(&mut verifying_key_serialized.as_slice())?;
    let proof = MarlinProof::deserialize(&mut proof_serialized.as_slice())?;
    let rng = &mut ark_std::test_rng();

    let result = MarlinInst::verify(&verifying_key, &public_inputs, &proof, rng)
        .map_err(|e| anyhow!("{:?}", e))?;

    Ok(result)
}
