use super::ConstraintF;
use anyhow::{anyhow, Result};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

pub fn serialize_field_element(field_element: ConstraintF) -> Result<Vec<u8>> {
    let mut bytes_field_element = Vec::new();
    field_element
        .serialize_uncompressed(&mut bytes_field_element)
        .map_err(|e| anyhow!("Error serializing proof: {e:?}"))?;
    Ok(bytes_field_element)
}

pub fn deserialize_field_element(bytes_field_element: Vec<u8>) -> Result<ConstraintF> {
    ConstraintF::deserialize_uncompressed(&mut bytes_field_element.as_slice())
        .map_err(|e| anyhow!("Error deserializing field element: {e:?}"))
}

#[allow(clippy::print_stdout)]
#[cfg(test)]
mod tests {
    use super::serialize_field_element;
    use crate::fields::ConstraintF;
    use ark_ff::UniformRand;

    #[test]
    fn test_serialize_field_element() {
        let nonce = ConstraintF::rand(&mut ark_std::test_rng());

        let v = serialize_field_element(nonce).unwrap();

        println!("{v:?}");
    }
}
