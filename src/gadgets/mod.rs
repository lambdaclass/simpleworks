use ark_r1cs_std::uint64::UInt64;

mod address;
pub use address::Address;

pub mod record;
pub use record::Record;

pub type ConstraintF = ark_ed_on_bls12_381::Fq;

pub type UInt64Gadget = UInt64<ConstraintF>;
pub type AddressGadget = Address<ConstraintF>;
