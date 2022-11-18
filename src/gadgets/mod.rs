pub mod int16;
pub mod int32;
pub mod int64;
pub mod int8;

// Note: This use is not public so we're enforcing the users to use Int8Gadget.
use int8::Int8;
// Note: This use is not public so we're enforcing the users to use Int16Gadget.
use int16::Int16;
// Note: This use is not public so we're enforcing the users to use Int32Gadget.
use int32::Int32;
// Note: This use is not public so we're enforcing the users to use Int64Gadget.
use int64::Int64;

pub type ConstraintF = ark_ed_on_bls12_381::Fq;

pub type Int8Gadget = Int8<ConstraintF>;
pub type Int16Gadget = Int16<ConstraintF>;
pub type Int32Gadget = Int32<ConstraintF>;
pub type Int64Gadget = Int64<ConstraintF>;
