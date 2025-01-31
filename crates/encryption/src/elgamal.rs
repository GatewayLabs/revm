use crate::encryption_trait::Encryptor;
use curve25519_dalek::scalar::Scalar;
use solana_zk_sdk::encryption::elgamal::{ElGamalCiphertext, ElGamalKeypair, ElGamalPubkey};

pub struct ElGamalEncryption;

pub type PublicKey = ElGamalPubkey;
pub type Keypair = ElGamalKeypair;
pub type Ciphertext = ElGamalCiphertext;

impl Encryptor for ElGamalEncryption {
    type PublicKey = PublicKey;
    type Keypair = Keypair;
    type Ciphertext = Ciphertext;

    /// Encrypt data using ElGamal public key with proper padding
    fn encrypt(data: &[u8], public_key: &Self::PublicKey) -> Self::Ciphertext {
        // Ensure data is padded to 32 bytes for scalar conversion
        let mut padded_data = [0u8; 32]; // Create a zeroed 32-byte array
        let data_len = data.len().min(32); // Ensure it doesn't overflow
        padded_data[..data_len].copy_from_slice(&data[..data_len]); // Pad the data

        let scalar_value =
            Scalar::from_canonical_bytes(padded_data).expect("Failed to convert data into Scalar.");

        public_key.encrypt(scalar_value)
    }

    /// Decrypt data using the ElGamal ciphertext's own method
    fn decrypt(ciphertext: &Self::Ciphertext, private_key: &Self::Keypair) -> Result<Vec<u8>, String> {
        // Attempt to decrypt directly using the ciphertext's decryption method
        match ciphertext.decrypt_u32(&private_key.secret()) {
            Some(value) => Ok(value.to_le_bytes().to_vec()), // Convert u32 back to bytes
            None => Err("Decryption failed".to_string()),
        }
    }
}
