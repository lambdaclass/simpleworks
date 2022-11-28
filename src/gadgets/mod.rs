use ark_r1cs_std::uint128::UInt128;
use ark_r1cs_std::uint16::UInt16;
use ark_r1cs_std::uint32::UInt32;
use ark_r1cs_std::uint64::UInt64;
use ark_r1cs_std::uint8::UInt8;

mod address;
pub use address::Address;
pub mod traits;
mod uint128;
mod uint16;
mod uint32;
mod uint64;
mod uint8;

pub type ConstraintF = ark_ed_on_bls12_381::Fq;

pub type UInt8Gadget = UInt8<ConstraintF>;
pub type UInt16Gadget = UInt16<ConstraintF>;
pub type UInt32Gadget = UInt32<ConstraintF>;
pub type UInt64Gadget = UInt64<ConstraintF>;
pub type UInt128Gadget = UInt128<ConstraintF>;
pub type AddressGadget = Address<ConstraintF>;
