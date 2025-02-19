/// Trait for encryption abstraction to support multiple algorithms
pub trait Encryptor {
    type PublicKey;
    type Keypair;
    type Ciphertext;

    /// Encrypt a serialized message
    fn encrypt(data: &[u8], public_key: &Self::PublicKey) -> Self::Ciphertext;

    /// Decrypt a ciphertext and return the original data
    fn decrypt(ciphertext: &Self::Ciphertext, private_key: &Self::Keypair) -> Result<Vec<u8>, String>;
}
