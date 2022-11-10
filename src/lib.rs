#![warn(warnings, rust_2018_idioms)]
#![forbid(unsafe_code)]
#![recursion_limit = "256"]
#![warn(
    clippy::allow_attributes_without_reason,
    clippy::as_conversions,
    clippy::unnecessary_cast,
    clippy::clone_on_ref_ptr,
    clippy::create_dir,
    clippy::dbg_macro,
    clippy::decimal_literal_representation,
    clippy::default_numeric_fallback,
    clippy::deref_by_slicing,
    clippy::empty_structs_with_brackets,
    clippy::float_cmp_const,
    clippy::fn_to_numeric_cast_any,
    clippy::indexing_slicing,
    clippy::let_underscore_must_use,
    clippy::map_err_ignore,
    clippy::single_char_lifetime_names,
    clippy::str_to_string,
    clippy::string_add,
    clippy::string_slice,
    clippy::string_to_string,
    clippy::todo,
    clippy::try_err,
    clippy::unseparated_literal_suffix
)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![allow(clippy::module_inception, clippy::module_name_repetitions)]

pub mod marlin;
pub mod merkle_tree;

#[macro_use]
extern crate derivative;

pub type Error = Box<dyn ark_std::error::Error>;

#[macro_export]
/// Convert any serializable object to uncompressed bytes.
macro_rules! to_uncompressed_bytes {
    ($v: expr) => {{
        let mut bytes = Vec::new();
        let result = $v.borrow().serialize_uncompressed(&mut bytes);
        if let Ok(()) = result {
            Ok(bytes)
        } else {
            Err(result.err().unwrap())
        }
    }};
}
