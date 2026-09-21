use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("secure randomness is unavailable: {0}")]
    Randomness(#[source] rand::rngs::SysError),
    #[error("X25519 produced a non-contributory shared secret")]
    NonContributoryKeyAgreement,
    #[error("HKDF key derivation failed")]
    KeyDerivation,
    #[error("invalid AEAD key length")]
    InvalidKey,
    #[error("packet encryption failed")]
    Encryption,
    #[error("packet authentication failed")]
    AuthenticationFailed,
    #[error("obfuscated datagram is too short to contain a valid envelope")]
    ObfuscationTooShort,
    #[error("invalid Ed25519 identity key encoding")]
    InvalidIdentityKey,
}
