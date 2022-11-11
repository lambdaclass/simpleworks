/*
pub fn check_leave_exists_u8<L: ToBytes>(tree: &SimpleMerkleTree, leaf: u8, path: Path<MerkleConfig>) -> Result<bool> {
    // get the root
    let root = tree.root();

    let circuit = MerkleTreeVerificationU8 {
        // constants
        leaf_crh_params,
        two_to_one_crh_params,

        // public inputs
        root,
        leaf,

        // witness
        authentication_path: Some(proof),
    };

    // Next, let's make the circuit!
    let cs = ConstraintSystem::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    // Let's check whether the constraint system is satisfied
    let is_satisfied = cs.is_satisfied().unwrap();
    if !is_satisfied {
        // If it isn't, find out the offending constraint.
        println!("{:?}", cs.which_is_unsatisfied());
    }
    assert!(is_satisfied);
}
*/

/*
#[cfg(test)]
mod tests {
    //MerkleTreeVerification, TwoToOneCRH, CRH
    use crate::merkle_tree::common::{LeafHash, TwoToOneHash};
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_marlin::{Marlin, SimpleHashFiatShamirRng};
    use ark_poly::univariate::DensePolynomial;
    use ark_poly_commit::marlin_pc::MarlinKZG10;
    use ark_r1cs_std::{boolean::Boolean, uint8::UInt8};
    use ark_relations::r1cs::{
        ConstraintLayer, ConstraintSynthesizer, ConstraintSystem, TracingMode,
    };
    use blake2::Blake2s;
    use rand_chacha::ChaChaRng;
    use tracing_subscriber::layer::SubscriberExt;

    /*
        use ark_bls12_381::{Bls12_381, Fr};
    use ark_marlin::{Marlin, SimpleHashFiatShamirRng};
    use ark_poly::univariate::DensePolynomial;
    use ark_poly_commit::marlin_pc::MarlinKZG10;
    use blake2::Blake2s;
    use rand_chacha::ChaChaRng;

    type MultiPC = MarlinKZG10<Bls12_381, DensePolynomial<Fr>>;
    type FS = SimpleHashFiatShamirRng<Blake2s, ChaChaRng>;
    type MarlinInst = Marlin<Fr, MultiPC, FS>;
    */
    // Run this test via `cargo test --release test_merkle_tree`.
    #[test]
    fn merkle_tree_constraints_correctness() {
        let tree = crate::merkle_tree::SimpleMerkleTree::new_simple_merkle_tree(&[
            1u8, 2u8, 3u8, 10u8, 9u8, 17u8, 70u8, 45u8,
        ])
        .unwrap();

        // proof for the 5th element
        let path = tree.generate_proof(4).unwrap();

        // call marlin fn to get proof
    }
}
*/

/*
*/

/*
{
    // Run this test via `cargo test --release test_merkle_tree_constraints_soundness`.
    // This tests that a given invalid authentication path will fail.
    #[test]
    fn merkle_tree_constraints_soundness() {
        // Let's set up an RNG for use within tests. Note that this is *not* safe
        // for any production use.
        let mut rng = ark_std::test_rng();

        // First, let's sample the public parameters for the hash functions:
        let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
        let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

        // Next, let's construct our tree.
        // This follows the API in https://github.com/arkworks-rs/crypto-primitives/blob/6be606259eab0aec010015e2cfd45e4f134cd9bf/src/merkle_tree/mod.rs#L156
        let tree = super::SimpleMerkleTree::new(
            &leaf_crh_params,
            &two_to_one_crh_params,
            &[1u8, 2u8, 3u8, 10u8, 9u8, 17u8, 70u8, 45u8], // the i-th entry is the i-th leaf.
        )
        .unwrap();

        // We just mutate the first leaf
        let second_tree = super::SimpleMerkleTree::new(
            &leaf_crh_params,
            &two_to_one_crh_params,
            &[4u8, 2u8, 3u8, 10u8, 9u8, 17u8, 70u8, 45u8], // the i-th entry is the i-th leaf.
        )
        .unwrap();

        // Now, let's try to generate a membership proof for the 5th item, i.e. 9.
        let proof = tree.generate_proof(4).unwrap(); // we're 0-indexing!

        // But, let's get the root we want to verify against:
        let wrong_root = second_tree.root();

        let circuit = MerkleTreeVerification {
            // constants
            leaf_crh_params,
            two_to_one_crh_params,

            // public inputs
            root: wrong_root,
            leaf: 9u8,

            // witness
            authentication_path: Some(proof),
        };
        // First, some boilerplate that helps with debugging
        let mut layer = ConstraintLayer::default();
        layer.mode = TracingMode::OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);

        // Next, let's make the constraint system!
        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        // Let's check whether the constraint system is satisfied
        let is_satisfied = cs.is_satisfied().unwrap();
        // We expect this to fail!
        assert!(!is_satisfied);
    }*/
/*
    #[test]
    fn merkle_tree_test_proof() {
        let mut rng = ark_std::test_rng();
        let universal_srs = MarlinInst::universal_setup(100000, 25000, 300000, &mut rng).unwrap();

        // First, let's sample the public parameters for the hash functions:
        let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
        let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

        // Next, let's construct our tree.
        // This follows the API in https://github.com/arkworks-rs/crypto-primitives/blob/6be606259eab0aec010015e2cfd45e4f134cd9bf/src/merkle_tree/mod.rs#L156
        let tree = super::SimpleMerkleTree::new(
            &leaf_crh_params,
            &two_to_one_crh_params,
            &[1u8, 2u8, 3u8, 10u8, 9u8, 17u8, 70u8, 45u8], // the i-th entry is the i-th leaf.
        )
        .unwrap();

        // Now, let's try to generate a membership proof for the 5th item, i.e. 9.
        // This should be a proof for the membership of a leaf with value 9. Let's check that!
        let proof = tree.generate_proof(4).unwrap();

        // First, let's get the root we want to verify against:
        let root = tree.root();

        let circuit = MerkleTreeVerification {
            // constants
            leaf_crh_params,
            two_to_one_crh_params,

            // public inputs
            root,
            leaf: 9u8,

            // witness
            authentication_path: Some(proof),
        };

        // Now, try to generate the verifying key and proving key with Marlin
        let (index_pk, index_vk) = MarlinInst::index(&universal_srs, circuit.clone()).unwrap();

        // generate the proof
        let proof = MarlinInst::prove(&index_pk, circuit.clone(), &mut rng).unwrap();


        let v: UInt8<Fr> = UInt8::constant(9u8);

        //to_bits_le()

        // check the proof
        let one = Fr::from(Boolean::TRUE);
        let zero = Fr::from(0);
        let inputs = vec![root, one, zero, zero, one, zero, zero, zero, zero];
        assert!(MarlinInst::verify(&index_vk, &inputs, &proof, &mut rng).unwrap());
    }
}
*/
