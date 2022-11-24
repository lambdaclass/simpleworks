use ark_r1cs_std::uint64::UInt64;

pub mod record;
pub use record::Record;

pub type ConstraintF = ark_ed_on_bls12_381::Fq;

pub type UInt64Gadget = UInt64<ConstraintF>;
