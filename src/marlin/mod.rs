use ark_bls12_381::{Bls12_381, Fr};
use ark_marlin::{Marlin, SimpleHashFiatShamirRng};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::marlin_pc::MarlinKZG10;
use blake2::Blake2s;
use rand_chacha::ChaChaRng;

pub type MultiPC = MarlinKZG10<Bls12_381, DensePolynomial<Fr>>;
pub type FS = SimpleHashFiatShamirRng<Blake2s, ChaChaRng>;
pub type MarlinInst = Marlin<Fr, MultiPC, FS>;
