use bytes::Bytes;
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{
    CryptoError, Secret, SharedSecret,
    constants::{INFO_C2S, INFO_S2C, KEY_LEN, NONCE_LEN, PSK_LEN},
};

pub struct HandshakePsk(Secret<PSK_LEN>);

impl HandshakePsk {
    pub fn from_bytes(bytes: [u8; PSK_LEN]) -> Self {
        Self(Secret::from_bytes(bytes))
    }

    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self(Secret::random()?))
    }

    pub fn authenticate(&self, data: &[u8]) -> [u8; PSK_LEN] {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.0.as_bytes())
            .expect("fixed-length HMAC keys are always accepted");
        mac.update(data);
        mac.finalize().into_bytes().into()
    }

    pub fn verify(&self, data: &[u8], tag: &[u8; PSK_LEN]) -> bool {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.0.as_bytes())
            .expect("fixed-length HMAC keys are always accepted");
        mac.update(data);
        mac.verify_slice(tag).is_ok()
    }
}

impl core::fmt::Debug for HandshakePsk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HandshakePsk([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionRole {
    Initiator,
    Responder,
}

#[derive(Clone)]
pub struct SessionKeys {
    send: Secret<KEY_LEN>,
    receive: Secret<KEY_LEN>,
}

impl SessionKeys {
    pub fn derive(
        shared: SharedSecret,
        transcript_hash: &[u8; KEY_LEN],
        role: SessionRole,
    ) -> Result<Self, CryptoError> {
        let hkdf = Hkdf::<Sha256>::new(Some(transcript_hash), shared.0.as_bytes());
        let mut c2s = [0; KEY_LEN];
        let mut s2c = [0; KEY_LEN];
        hkdf.expand(INFO_C2S, &mut c2s)
            .map_err(|_| CryptoError::KeyDerivation)?;
        hkdf.expand(INFO_S2C, &mut s2c)
            .map_err(|_| CryptoError::KeyDerivation)?;
        let (send, receive) = match role {
            SessionRole::Initiator => (c2s, s2c),
            SessionRole::Responder => (s2c, c2s),
        };
        Ok(Self {
            send: Secret::from_bytes(send),
            receive: Secret::from_bytes(receive),
        })
    }

    pub fn seal(
        &self,
        nonce: PacketNonce,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Bytes, CryptoError> {
        crypt(true, self.send.as_bytes(), nonce, aad, plaintext)
    }

    pub fn open(
        &self,
        nonce: PacketNonce,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Bytes, CryptoError> {
        crypt(false, self.receive.as_bytes(), nonce, aad, ciphertext)
    }
}

impl core::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SessionKeys([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketNonce([u8; NONCE_LEN]);

impl PacketNonce {
    pub fn from_sequence(key_phase: u32, sequence: u64) -> Self {
        let mut bytes = [0; NONCE_LEN];
        bytes[..4].copy_from_slice(&key_phase.to_be_bytes());
        bytes[4..].copy_from_slice(&sequence.to_be_bytes());
        Self(bytes)
    }
}

fn crypt(
    encrypt: bool,
    key: &[u8; KEY_LEN],
    nonce: PacketNonce,
    aad: &[u8],
    input: &[u8],
) -> Result<Bytes, CryptoError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
    let payload = Payload { msg: input, aad };
    let result = if encrypt {
        cipher
            .encrypt(&Nonce::from(nonce.0), payload)
            .map_err(|_| CryptoError::Encryption)
    } else {
        cipher
            .decrypt(&Nonce::from(nonce.0), payload)
            .map_err(|_| CryptoError::AuthenticationFailed)
    };
    result.map(Bytes::from)
}
