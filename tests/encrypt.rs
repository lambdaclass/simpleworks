mod tests {
    use anyhow::anyhow;
    use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305};
    use rand::{rngs::OsRng, RngCore};

    fn encrypt_helper(
        file_data: &[u8],
        key: &[u8; 32],
        nonce: &[u8; 24],
    ) -> Result<Vec<u8>, anyhow::Error> {
        let cipher = XChaCha20Poly1305::new(key.into());
        cipher
            .encrypt(nonce.into(), file_data.as_ref())
            .map_err(|err| anyhow!("Encrypting small file: {}", err))
    }

    fn decrypt_helper(
        encrypted_data: &[u8],
        key: &[u8; 32],
        nonce: &[u8; 24],
    ) -> Result<Vec<u8>, anyhow::Error> {
        let cipher = XChaCha20Poly1305::new(key.into());
        cipher
            .decrypt(nonce.into(), encrypted_data.as_ref())
            .map_err(|err| anyhow!("Decrypting small file: {}", err))
    }

    #[test]
    fn encrypt() {
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut key);
        OsRng.fill_bytes(&mut nonce);

        let file_data = b"hello world";
        let e = encrypt_helper(file_data, &key, &nonce).unwrap();

        let ret = decrypt_helper(&e, &key, &nonce).unwrap();
        let ret_str = std::str::from_utf8(&ret).unwrap();
        println!("{:?}", e);
        println!("{:?}", ret_str);
    }
}
