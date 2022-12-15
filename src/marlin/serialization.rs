use super::{MarlinProof, ProvingKey, VerifyingKey};
use anyhow::{anyhow, Result};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

pub fn serialize_proof(proof: MarlinProof) -> Result<Vec<u8>> {
    let mut bytes_proof = Vec::new();
    proof
        .serialize(&mut bytes_proof)
        .map_err(|e| anyhow!("Error serializing proof: {e:?}"))?;

    Ok(bytes_proof)
}

pub fn deserialize_proof(bytes_proof: Vec<u8>) -> Result<MarlinProof> {
    MarlinProof::deserialize(&mut bytes_proof.as_slice())
        .map_err(|e| anyhow!("Error deserializing proof: {e:?}"))
}

pub fn serialize_verifying_key(verifying_key: VerifyingKey) -> Result<Vec<u8>> {
    let mut bytes_verifying_key = Vec::new();
    verifying_key
        .serialize(&mut bytes_verifying_key)
        .map_err(|e| anyhow!("Error serializing verifying key: {e:?}"))?;

    Ok(bytes_verifying_key)
}

pub fn deserialize_verifying_key(bytes_verifying_key: Vec<u8>) -> Result<VerifyingKey> {
    VerifyingKey::deserialize(&mut bytes_verifying_key.as_slice())
        .map_err(|e| anyhow!("Error deserializing verifying key: {e:?}"))
}

pub fn serialize_proving_key(proving_key: ProvingKey) -> Result<Vec<u8>> {
    let mut bytes_proving_key = Vec::new();
    proving_key
        .serialize(&mut bytes_proving_key)
        .map_err(|e| anyhow!("Error serializing proving key: {e:?}"))?;

    Ok(bytes_proving_key)
}

pub fn deserialize_proving_key(bytes_proving_key: Vec<u8>) -> Result<ProvingKey> {
    ProvingKey::deserialize(&mut bytes_proving_key.as_slice())
        .map_err(|e| anyhow!("Error deserializing proving key: {e:?}"))
}
