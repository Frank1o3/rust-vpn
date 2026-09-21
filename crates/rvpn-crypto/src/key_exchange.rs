use x25519_dalek::{PublicKey, StaticSecret};

use crate::{CryptoError, Secret};
use crate::KEY_LEN;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicKeyBytes([u8; KEY_LEN]);

impl PublicKeyBytes {
    pub const fn new(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub const fn to_bytes(self) -> [u8; KEY_LEN] {
        self.0
    }
}

pub struct EphemeralKeyPair {
    secret: StaticSecret,
    public: PublicKeyBytes,
}

impl EphemeralKeyPair {
    pub fn generate() -> Result<Self, CryptoError> {
        let bytes = Secret::<KEY_LEN>::random()?.0;
        let secret = StaticSecret::from(bytes);
        let public = PublicKeyBytes::new(PublicKey::from(&secret).to_bytes());
        Ok(Self { secret, public })
    }

    pub const fn public_key(&self) -> PublicKeyBytes {
        self.public
    }

    pub fn agree(self, peer: PublicKeyBytes) -> Result<SharedSecret, CryptoError> {
        let bytes = self
            .secret
            .diffie_hellman(&PublicKey::from(peer.0))
            .to_bytes();
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(CryptoError::NonContributoryKeyAgreement);
        }
        Ok(SharedSecret(Secret::from_bytes(bytes)))
    }
}

pub struct SharedSecret(Secret<KEY_LEN>);

impl core::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SharedSecret([REDACTED])")
    }
}


