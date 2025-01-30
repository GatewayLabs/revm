use primitives::U256;

/// Trait for encryption abstraction to support multiple algorithms
pub trait Encryptor {
    type PublicKey;
    type Keypair;
    type Ciphertext;

    /// Encrypt a serialized message
    fn encrypt(data: &[u8], public_key: &Self::PublicKey) -> Self::Ciphertext;

    /// Decrypt a ciphertext and return the original data
    fn decrypt(ciphertext: &Self::Ciphertext, private_key: &Self::Keypair) -> Option<Vec<u8>>;

    /// Decrypt a ciphertext and return the original data as a U256
    fn decrypt_to_u256(ciphertext: &Self::Ciphertext, private_key: &Self::Keypair) -> U256;
}
