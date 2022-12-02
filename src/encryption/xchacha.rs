use aead::{AeadInPlace, Key, NewAead, Nonce};
use anyhow::{anyhow, Result};
use std::ops::Deref;
use xchacha8blake3siv::XChaCha8Blake3Siv;

pub fn encrypt_buffer(
    text_key: &[u8; 32],
    text_nonce: &[u8; 24],
    associated_data: &[u8],
    buffer: &mut [u8],
) -> Result<Vec<u8>> {
    let key = Key::<XChaCha8Blake3Siv>::from_slice(text_key);

    let cipher = XChaCha8Blake3Siv::new(key);
    let nonce = Nonce::<XChaCha8Blake3Siv>::from_slice(text_nonce);

    let tag = cipher
        .encrypt_in_place_detached(nonce, associated_data, buffer)
        .map_err(|e| anyhow!("{}", e))?;

    Ok(Vec::<u8>::from(tag.deref()))
}
