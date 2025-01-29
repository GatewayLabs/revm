#[cfg(test)]
mod tests {
    use revm_encryption::elgamal::ElGamalEncryption;
    use revm_encryption::encryption_trait::Encryptor;
    use solana_zk_sdk::encryption::elgamal::ElGamalKeypair;

    /// ✅ Test basic encryption and decryption with valid data
    #[test]
    fn test_elgamal_encryption_decryption() {
        let keypair = ElGamalKeypair::new_rand();
        let public_key = keypair.pubkey();
        let data = 42u64.to_le_bytes(); // Proper 8-byte integer padded

        // Encrypt and decrypt
        let encrypted_data = ElGamalEncryption::encrypt(&data, &public_key);
        let decrypted_data =
            ElGamalEncryption::decrypt(&encrypted_data, &keypair).expect("Decryption failed");

        // Verify if the original data matches the decrypted result
        assert_eq!(
            data.to_vec(),
            decrypted_data[..8],
            "Decrypted data does not match the original!"
        );
    }

    /// ✅ Test zero value encryption and decryption
    #[test]
    fn test_zero_value_encryption_decryption() {
        let keypair = ElGamalKeypair::new_rand();
        let public_key = keypair.pubkey();
        let data = 0u64.to_le_bytes(); // Zero represented as 8 bytes

        let encrypted_data = ElGamalEncryption::encrypt(&data, &public_key);
        let decrypted_data =
            ElGamalEncryption::decrypt(&encrypted_data, &keypair).expect("Decryption failed");

        assert_eq!(
            data.to_vec(),
            decrypted_data[..8],
            "Decrypted zero value mismatch!"
        );
    }

    /// ✅ Test decryption with a different keypair (should fail)
    #[test]
    fn test_different_keypair_should_fail() {
        let keypair_1 = ElGamalKeypair::new_rand();
        let keypair_2 = ElGamalKeypair::new_rand();
        let public_key_1 = keypair_1.pubkey();

        let data = 42u64.to_le_bytes();

        // Encrypt using keypair_1's public key
        let encrypted_data = ElGamalEncryption::encrypt(&data, &public_key_1);

        // Attempt to decrypt with a different keypair
        let decrypted_data = ElGamalEncryption::decrypt(&encrypted_data, &keypair_2);
        assert!(
            decrypted_data.is_none(),
            "Decryption with different keypair should fail!"
        );
    }
}
