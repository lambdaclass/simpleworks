use ark_ec::ProjectiveCurve;
use ark_ed_on_bls12_377::{constraints::EdwardsVar, EdwardsProjective};
use ark_ff::Field;

pub mod schnorr;
pub use schnorr::{Parameters, PublicKey, SecretKey, Signature};

pub mod parameters_var;
pub use parameters_var::ParametersVar;

pub mod signature_var;
pub use signature_var::SignatureVar;

pub mod public_key_var;
pub use public_key_var::PublicKeyVar;

pub mod schnorr_signature_verify_gadget;
pub use schnorr_signature_verify_gadget::SchnorrSignatureVerifyGadget;

pub mod blake2s;
pub use blake2s::ParametersVar as Blake2sParametersVar;

use self::schnorr::Schnorr;

pub type ConstraintF<C> = <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField;

pub type SimpleSchnorrConstraintF =
    <<EdwardsProjective as ProjectiveCurve>::BaseField as Field>::BasePrimeField;

pub type SimpleSchnorrParameters = Parameters<EdwardsProjective>;
pub type SimpleSchnorrPublicKey = PublicKey<EdwardsProjective>;
pub type SimpleSchnorrSignature = Signature<EdwardsProjective>;
pub type SimpleSchnorrMessage = Vec<u8>;

pub type SimpleSchnorrParametersVar = ParametersVar<EdwardsProjective, EdwardsVar>;
pub type SimpleSchnorrPublicKeyVar = PublicKeyVar<EdwardsProjective, EdwardsVar>;
pub type SimpleSchnorrSignatureVar = SignatureVar<EdwardsProjective, EdwardsVar>;

pub type SimpleSchnorr = Schnorr<EdwardsProjective>;
