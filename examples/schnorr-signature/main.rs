use ark_crypto_primitives::signature::SigVerifyGadget;
use ark_r1cs_std::{
    prelude::{AllocVar, Boolean, EqGadget},
    uint8::UInt8,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use simpleworks::schnorr_signature::*;

#[derive(Clone)]
pub struct SimpleSchnorrSignatureVerification {
    parameters: SimpleSchnorrParameters,
    // The public key of the signer.
    public_key: SimpleSchnorrPublicKey,
    // The signed message.
    message: SimpleSchnorrMessage,
    // The signature of the message.
    signature: SimpleSchnorrSignature,
}

impl ConstraintSynthesizer<SimpleSchnorrConstraintF> for SimpleSchnorrSignatureVerification {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<SimpleSchnorrConstraintF>,
    ) -> Result<(), SynthesisError> {
        // First we allocate the parameters.
        let parameters = SimpleSchnorrParametersVar::new_constant(
            ark_relations::ns!(cs, "parameters"),
            self.parameters,
        )?;

        // Then we allocate the public key.
        let public_key =
            SimpleSchnorrPublicKeyVar::new_witness(ark_relations::ns!(cs, "public_key"), || {
                Ok(&self.public_key)
            })?;

        // Then we allocate the message.
        // let message = UInt8::new_input_vec(ark_relations::ns!(cs, "message"), &self.message)?;
        let mut message = Vec::new();
        for i in 0..self.message.len() {
            message.push(UInt8::new_witness(cs.clone(), || Ok(&self.message[i])).unwrap())
        }

        // Then we allocate the signature.
        let signature =
            SimpleSchnorrSignatureVar::new_witness(ark_relations::ns!(cs, "signature"), || {
                Ok(&self.signature)
            })?;

        // Finally we verify the signature.
        let result =
            SchnorrSignatureVerifyGadget::verify(&parameters, &public_key, &message, &signature);

        result?.enforce_equal(&Boolean::Constant(true))?;

        Ok(())
    }
}

fn main() {}

#[cfg(test)]
mod test {
    use crate::*;
    use ark_bls12_377::{Bls12_377, Fr};
    use ark_crypto_primitives::SignatureScheme;
    use ark_marlin::{Marlin, SimpleHashFiatShamirRng};
    use ark_poly::univariate::DensePolynomial;
    use ark_poly_commit::marlin_pc::MarlinKZG10;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::test_rng;
    use blake2::Blake2s;
    use rand_chacha::ChaChaRng;

    type MultiPC = MarlinKZG10<Bls12_377, DensePolynomial<Fr>>;
    type FS = SimpleHashFiatShamirRng<Blake2s, ChaChaRng>;
    type MarlinInst = Marlin<Fr, MultiPC, FS>;

    fn sign_and_verify(message: &[u8]) {
        let rng = &mut test_rng();
        let parameters = SimpleSchnorr::setup::<_>(rng).unwrap();
        let (pk, sk) = SimpleSchnorr::keygen(&parameters, rng).unwrap();
        let sig = SimpleSchnorr::sign(&parameters, &sk, &message, rng).unwrap();
        assert!(SimpleSchnorr::verify(&parameters, &pk, &message, &sig).unwrap());
    }

    fn failed_verification(message: &[u8], bad_message: &[u8]) {
        let rng = &mut test_rng();
        let parameters = SimpleSchnorr::setup::<_>(rng).unwrap();
        let (pk, sk) = SimpleSchnorr::keygen(&parameters, rng).unwrap();
        let sig = SimpleSchnorr::sign(&parameters, &sk, message, rng).unwrap();
        assert!(!SimpleSchnorr::verify(&parameters, &pk, bad_message, &sig).unwrap());
    }

    #[test]
    fn schnorr_signature_test() {
        let message = b"hello world";
        let bad_message = b"goodbye world";
        sign_and_verify(message);
        failed_verification(message, bad_message);
    }

    #[test]
    fn test01_valid_signature() {
        // Let's set up an RNG for use within tests. Note that this is *not* safe
        // for any production use.
        let rng = &mut test_rng();

        // First, we set up the parameters for the signature scheme.
        let parameters = SimpleSchnorr::setup::<_>(rng).unwrap();
        // Then we generate a keypair.
        let (pk, sk) = SimpleSchnorr::keygen(&parameters, rng).unwrap();
        // Then we sign a message.
        let message = b"hello world";
        let signature = SimpleSchnorr::sign(&parameters, &sk, message, rng).unwrap();

        // Now we create a constraint system and the circuit that will verify
        // the signature.
        let cs = ConstraintSystem::<SimpleSchnorrConstraintF>::new_ref();
        let circuit = SimpleSchnorrSignatureVerification {
            parameters,
            public_key: pk,
            message: message.to_vec(),
            signature,
        };
        // We generate the constraints for the circuit.
        circuit.generate_constraints(cs.clone()).unwrap();
        // Let's check whether the constraint system is satisfied.
        let is_satisfied = cs.is_satisfied().unwrap();
        if !is_satisfied {
            // If it isn't, find out the offending constraint.
            println!("{:?}", cs.which_is_unsatisfied());
        }

        // Finally, we check that the constraint system is satisfied.
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test02_invalid_signature() {
        // Let's set up an RNG for use within tests. Note that this is *not* safe
        // for any production use.
        let rng = &mut test_rng();

        // First, we set up the parameters for the signature scheme.
        let parameters = SimpleSchnorr::setup::<_>(rng).unwrap();
        // Then we generate a keypair.
        let (pk, sk) = SimpleSchnorr::keygen(&parameters, rng).unwrap();
        // Then we sign a message.
        let message = b"hello world";
        let bad_message = b"goodbye world";
        let signature = SimpleSchnorr::sign(&parameters, &sk, message, rng).unwrap();

        // Now we create a constraint system and the circuit that will verify
        // the signature, but we'll send a bad message.
        let cs = ConstraintSystem::<SimpleSchnorrConstraintF>::new_ref();
        let circuit = SimpleSchnorrSignatureVerification {
            parameters,
            public_key: pk,
            message: bad_message.to_vec(),
            signature,
        };
        // We generate the constraints for the circuit.
        circuit.generate_constraints(cs.clone()).unwrap();
        // Let's check whether the constraint system is satisfied
        let is_satisfied = cs.is_satisfied().unwrap();
        if !is_satisfied {
            // If it isn't, find out the offending constraint.
            println!("{:?}", cs.which_is_unsatisfied());
        }

        // Finally, we check that the constraint system is satisfied.
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test03_valid_signature_marlin_proof() {
        // Let's set up an RNG for use within tests. Note that this is *not* safe
        // for any production use.
        let rng = &mut test_rng();

        // First, we set up the parameters for the signature scheme.
        let parameters = SimpleSchnorr::setup::<_>(rng).unwrap();
        // Then we generate a keypair.
        let (pk, sk) = SimpleSchnorr::keygen(&parameters, rng).unwrap();
        // Then we sign a message.
        let message = b"hello world";
        let signature = SimpleSchnorr::sign(&parameters, &sk, message, rng).unwrap();

        // And sample a random universal SRS.
        let universal_srs = MarlinInst::universal_setup(100000, 25000, 300000, rng).unwrap();

        // Now we create the circuit that will verify the signature.
        let circuit = SimpleSchnorrSignatureVerification {
            parameters,
            public_key: pk,
            message: message.to_vec(),
            signature,
        };

        // Now, try to generate the verifying key and proving key with Marlin.
        let (index_pk, index_vk) = MarlinInst::index(&universal_srs, circuit.clone()).unwrap();

        // Generate the proof.
        let proof = MarlinInst::prove(&index_pk, circuit.clone(), rng).unwrap();

        // Verify the proof.
        assert!(MarlinInst::verify(&index_vk, &[], &proof, rng).unwrap());
    }

    // TODO: Figure out why this test panics on a `debug_assert!` when verifying.
    // It might just be that we are proving a circuit that is not satisfied to begin with,
    // I'm not sure.
    #[test]
    #[should_panic(
        reason = "assertion failed: evals.get_lc_eval(&outer_sumcheck, beta)?.is_zero()"
    )]
    fn test04_invalid_signature_marlin_proof() {
        // Let's set up an RNG for use within tests. Note that this is *not* safe
        // for any production use.
        let rng = &mut test_rng();

        // First, we set up the parameters for the signature scheme.
        let parameters = SimpleSchnorr::setup::<_>(rng).unwrap();
        // Then we generate a keypair.
        let (pk, sk) = SimpleSchnorr::keygen(&parameters, rng).unwrap();
        // Then we sign a message.
        let message = b"hello world";
        let bad_message = b"goodbye world";
        let signature = SimpleSchnorr::sign(&parameters, &sk, message, rng).unwrap();

        // And sample a random universal SRS.
        let universal_srs = MarlinInst::universal_setup(100000, 25000, 300000, rng).unwrap();

        // Now we create the circuit that will verify the signature, but we'll
        // send a bad message.
        let circuit = SimpleSchnorrSignatureVerification {
            parameters,
            public_key: pk,
            message: bad_message.to_vec(),
            signature,
        };

        // Now, try to generate the verifying key and proving key with Marlin
        let (index_pk, index_vk) = MarlinInst::index(&universal_srs, circuit.clone()).unwrap();

        // Generate the proof.
        let proof = MarlinInst::prove(&index_pk, circuit.clone(), rng).unwrap();

        // Verify the proof.
        assert!(!MarlinInst::verify(&index_vk, &[], &proof, rng).unwrap());
    }
}
