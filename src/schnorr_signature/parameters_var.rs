use std::{borrow::Borrow, marker::PhantomData};

use ark_crypto_primitives::encryption::elgamal::constraints::ConstraintF;
use ark_ec::ProjectiveCurve;
use ark_r1cs_std::{
    prelude::{AllocVar, AllocationMode, CurveVar, GroupOpsBounds},
    uint8::UInt8,
};
use ark_relations::r1cs::{Namespace, SynthesisError};

use super::schnorr::Parameters;

#[derive(Clone)]
pub struct ParametersVar<C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>>
where
    for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
{
    pub(crate) generator: GC,
    pub(crate) salt: Option<Vec<UInt8<ConstraintF<C>>>>,
    _curve: PhantomData<C>,
}

impl<C, GC> AllocVar<Parameters<C>, ConstraintF<C>> for ParametersVar<C, GC>
where
    C: ProjectiveCurve,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
{
    fn new_variable<T: Borrow<Parameters<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();
            let generator = GC::new_variable(cs.clone(), || Ok(val.borrow().generator), mode)?;
            let native_salt = val.borrow().salt;
            let mut constraint_salt = Vec::<UInt8<ConstraintF<C>>>::new();
            if let Some(native_salt_value) = native_salt {
                for i in 0..32 {
                    if let Some(native_salt_element) = native_salt_value.get(i) {
                        constraint_salt.push(UInt8::<ConstraintF<C>>::new_variable(
                            cs.clone(),
                            || Ok(native_salt_element),
                            mode,
                        )?);
                    }
                }

                return Ok(Self {
                    generator,
                    salt: Some(constraint_salt),
                    _curve: PhantomData,
                });
            }
            Ok(Self {
                generator,
                salt: None,
                _curve: PhantomData,
            })
        })
    }
}
