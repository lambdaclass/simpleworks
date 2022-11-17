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

/// Return a cryptographically secure random number generator that uses the ChaCha algorithm.
/// 
pub fn generate_rand() -> StdRng {
    ark_std::test_rng()
}

///  Generate the universal prover and verifier keys for the argument system.
/// 
/// # Parameters.
/// - `rng` - A pseudorandom number generator (PRNG).
/// 
/// # Errors.
/// Send the literal 'Error generating universal srs'.
/// 
pub fn generate_universal_srs(rng: &mut StdRng) -> Result<UniversalSRS> {
    MarlinInst::universal_setup(100000, 25000, 300000, rng)
        .map_err(|_e| anyhow!("Error generating universal srs"))
}

///  Return a serialized version of the verifying key and proving key generated with Marlin and the universal_srs.
/// 
/// # Parameters.
/// - `universal_srs` - A universal prover and verifier keys for the argument system.
/// - `rng` - A pseudorandom number generator (PRNG).
/// - `constraint_system` - A shared reference to a constraint system that can be stored in high level variables.
/// 
/// # Errors
/// Literal 'Error in index_from_constraint_system' when the Marlin generation of the keys fail.
/// Literal 'Error in prove_from_constraint_system' when the Marlin proof of the proving key fail.
/// Literal 'Error serializing proof' when the process of serialization of the proving key fail.
/// Literal 'Error serializing verifying_key' when the process of serialization of the verifying key fail.
/// 
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
