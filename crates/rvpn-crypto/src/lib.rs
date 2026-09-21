mod auth;
mod constants;
mod cookie;
mod error;
mod identity;
mod key_exchange;
mod obfuscation;
mod secret;
mod session;

pub use auth::{AuthConfig, AuthIdentity, AuthVerifier};
pub use cookie::CookieKey;
pub use error::CryptoError;
pub use identity::{Certificate, IdentityKeyPair, IdentityPublicKey};
pub use key_exchange::{EphemeralKeyPair, PublicKeyBytes, SharedSecret};
pub use obfuscation::{OBFUSCATION_OVERHEAD, ObfuscationKey};
pub use secret::{Secret, random_bytes};
pub use session::{HandshakePsk, PacketNonce, SessionKeys, SessionRole};

use sha2::{Digest, Sha256};

pub fn transcript_hash(transcript: &[u8]) -> [u8; constants::KEY_LEN] {
    Sha256::digest(transcript).into()
}

#[cfg(test)]
mod tests;
