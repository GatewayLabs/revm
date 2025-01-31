pub mod elgamal;
pub mod encryption_trait;
pub use crate::elgamal::{Ciphertext, Keypair, PublicKey};
pub use crate::encryption_trait::Encryptor;