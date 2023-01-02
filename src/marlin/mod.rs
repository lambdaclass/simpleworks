use anyhow::{anyhow, Result};
use ark_bls12_377::{Bls12_377, Fr, FrParameters, Parameters};
use ark_ec::bls12::Bls12;
use ark_ff::Fp256;
use ark_marlin::{IndexProverKey, IndexVerifierKey, Marlin, Proof, SimpleHashFiatShamirRng};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::marlin_pc::MarlinKZG10;
use blake2::Blake2s;
use rand::rngs::StdRng;
use rand_chacha::ChaChaRng;

pub type MultiPC = MarlinKZG10<Bls12_377, DensePolynomial<Fr>>;
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

use crate::gadgets::ConstraintF;
pub mod serialization;

/// Return a pseudorandom number generator.
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
pub fn generate_universal_srs(
    num_constraints: usize,
    num_variables: usize,
    num_non_zero: usize,
    rng: &mut StdRng,
) -> Result<Box<UniversalSRS>> {
    Ok(Box::new(
        MarlinInst::universal_setup(num_constraints, num_variables, num_non_zero, rng)
            .map_err(|e| anyhow!("{:?}", e))?,
    ))
}

///  Return the serialized version of the marlin proof for the given circuit/constraint system.
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
    constraint_system: ConstraintSystemRef,
    proving_key: ProvingKey,
    rng: &mut StdRng,
) -> Result<MarlinProof> {
    MarlinInst::prove_from_constraint_system(&proving_key, constraint_system, rng)
        .map_err(|e| anyhow!("{:?}", e))
}

pub fn verify_proof(
    verifying_key: VerifyingKey,
    public_inputs: &[ConstraintF],
    proof: &MarlinProof,
    rng: &mut StdRng,
) -> Result<bool> {
    MarlinInst::verify(&verifying_key, public_inputs, proof, rng).map_err(|e| anyhow!("{:?}", e))
}

pub fn generate_proving_and_verifying_keys(
    universal_srs: &UniversalSRS,
    constraint_system: ConstraintSystemRef,
) -> Result<(ProvingKey, VerifyingKey)> {
    MarlinInst::index_from_constraint_system(universal_srs, constraint_system)
        .map_err(|e| anyhow!("{:?}", e))
}
