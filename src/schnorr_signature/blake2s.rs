use ark_crypto_primitives::prf::blake2s::constraints::{evaluate_blake2s, OutputVar};
use ark_crypto_primitives::Error;
use ark_ff::bytes::ToBytes;
use ark_ff::Field;
use ark_ff::PrimeField;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::Namespace;
use ark_relations::r1cs::SynthesisError;
use ark_std::hash::Hash;
use ark_std::rand::Rng;
use ark_std::vec::Vec;
use blake2::Blake2s as b2s;
use core::borrow::Borrow;
use core::fmt::Debug;
use digest::Digest;

/// Interface to a RandomOracle
pub trait RandomOracle {
    type Output: ToBytes + Clone + Eq + core::fmt::Debug + Hash + Default;
    type Parameters: Clone + Default;

    fn setup<R: Rng>(r: &mut R) -> Result<Self::Parameters, Error>;
    fn evaluate(parameters: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error>;
}

pub trait RandomOracleGadget<RO: RandomOracle, ConstraintF: Field>: Sized {
    type OutputVar: EqGadget<ConstraintF>
        + ToBytesGadget<ConstraintF>
        + AllocVar<RO::Output, ConstraintF>
        + R1CSVar<ConstraintF>
        + Debug
        + Clone
        + Sized;

    type ParametersVar: AllocVar<RO::Parameters, ConstraintF> + Clone;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &[UInt8<ConstraintF>],
    ) -> Result<Self::OutputVar, SynthesisError>;
}

pub struct RO;

impl RandomOracle for RO {
    type Parameters = ();
    type Output = [u8; 32];

    fn setup<R: Rng>(_: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    fn evaluate(_: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error> {
        let mut h = b2s::new();
        h.update(input);
        let mut result = [0_u8; 32];
        result.copy_from_slice(&h.finalize());
        Ok(result)
    }
}

#[derive(Clone)]
pub struct ParametersVar;

pub struct ROGadget;

impl<F: PrimeField> RandomOracleGadget<RO, F> for ROGadget {
    type OutputVar = OutputVar<F>;
    type ParametersVar = ParametersVar;

    fn evaluate(
        _: &Self::ParametersVar,
        input: &[UInt8<F>],
    ) -> Result<Self::OutputVar, SynthesisError> {
        let mut input_bits = Vec::with_capacity(512);
        for byte in input.iter() {
            input_bits.extend_from_slice(&byte.to_bits_le()?);
        }
        let mut result = Vec::new();
        for int in evaluate_blake2s(&input_bits)?.into_iter() {
            let chunk = int.to_bytes()?;
            result.extend_from_slice(&chunk);
        }
        Ok(OutputVar(result))
    }
}

impl<ConstraintF: Field> AllocVar<(), ConstraintF> for ParametersVar {
    fn new_variable<T: Borrow<()>>(
        _cs: impl Into<Namespace<ConstraintF>>,
        _f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        Ok(ParametersVar)
    }
}
