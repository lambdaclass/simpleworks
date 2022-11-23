pub mod uint64;

// Note: This use is not public so we're enforcing the users to use Int64Gadget.
use uint64::UInt64;

pub type ConstraintF = ark_ed_on_bls12_381::Fq;

pub type UInt64Gadget = UInt64<ConstraintF>;
