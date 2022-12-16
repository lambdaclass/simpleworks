#[cfg(test)]
mod tests {
    use ark_crypto_primitives::encryption::{
        elgamal::{ElGamal, Randomness},
        AsymmetricEncryptionScheme,
    };
    use ark_ed_on_bls12_377::EdwardsProjective as JubJub;
    use ark_std::{test_rng, UniformRand};

    type ElGamalCurve = ElGamal<JubJub>;
    #[test]
    fn test_elgamal_encryption() {
        let rng = &mut test_rng();

        // setup and key generation
        let parameters = ElGamalCurve::setup(rng).unwrap();
        let (pk, sk) = ElGamalCurve::keygen(&parameters, rng).unwrap();

        // get a random msg and encryption randomness
        let msg = JubJub::rand(rng).into();
        let r = Randomness::rand(rng);

        // encrypt and decrypt the message
        let cipher = ElGamalCurve::encrypt(&parameters, &pk, &msg, &r).unwrap();
        let check_msg = ElGamalCurve::decrypt(&parameters, &sk, &cipher).unwrap();

        assert_eq!(msg, check_msg);
    }
}
