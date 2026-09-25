use bytes::Bytes;
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::{
    CryptoError, Secret, SharedSecret,
    constants::{INFO_C2S, INFO_S2C, KEY_LEN, NONCE_LEN},
};

pub fn handshake_salt(initiation_bytes: &[u8], response_public_bytes: &[u8]) -> [u8; KEY_LEN] {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(initiation_bytes);
    hasher.update(response_public_bytes);
    hasher.finalize().into()
}

#[derive(Clone)]
pub struct HandshakeKeys {
    r2i: Secret<KEY_LEN>,
    i2r: Secret<KEY_LEN>,
}

impl HandshakeKeys {
    pub fn derive(shared: &SharedSecret, salt: &[u8; KEY_LEN]) -> Result<Self, CryptoError> {
        let hkdf = Hkdf::<Sha256>::new(Some(salt), shared.0.as_bytes());
        let mut r2i = [0; KEY_LEN];
        let mut i2r = [0; KEY_LEN];
        hkdf.expand(b"rvpn-v3/handshake/proof/r2i", &mut r2i)
            .map_err(|_| CryptoError::KeyDerivation)?;
        hkdf.expand(b"rvpn-v3/handshake/proof/i2r", &mut i2r)
            .map_err(|_| CryptoError::KeyDerivation)?;
        Ok(Self {
            r2i: Secret::from_bytes(r2i),
            i2r: Secret::from_bytes(i2r),
        })
    }

    pub fn derive_from_transcript(
        shared: &SharedSecret,
        initiation_bytes: &[u8],
        response_public_bytes: &[u8],
    ) -> Result<Self, CryptoError> {
        let salt = handshake_salt(initiation_bytes, response_public_bytes);
        Self::derive(shared, &salt)
    }

    pub fn seal_response(&self, aad: &[u8], plaintext: &[u8]) -> Result<Bytes, CryptoError> {
        self.crypt_fixed_nonce(true, self.r2i.as_bytes(), aad, plaintext)
    }

    pub fn open_response(&self, aad: &[u8], ciphertext: &[u8]) -> Result<Bytes, CryptoError> {
        self.crypt_fixed_nonce(false, self.r2i.as_bytes(), aad, ciphertext)
    }

    pub fn seal_finish(&self, aad: &[u8], plaintext: &[u8]) -> Result<Bytes, CryptoError> {
        self.crypt_fixed_nonce(true, self.i2r.as_bytes(), aad, plaintext)
    }

    pub fn open_finish(&self, aad: &[u8], ciphertext: &[u8]) -> Result<Bytes, CryptoError> {
        self.crypt_fixed_nonce(false, self.i2r.as_bytes(), aad, ciphertext)
    }

    pub fn r2i_key(&self) -> &[u8; KEY_LEN] {
        self.r2i.as_bytes()
    }

    pub fn i2r_key(&self) -> &[u8; KEY_LEN] {
        self.i2r.as_bytes()
    }

    fn crypt_fixed_nonce(
        &self,
        encrypt: bool,
        key: &[u8; KEY_LEN],
        aad: &[u8],
        input: &[u8],
    ) -> Result<Bytes, CryptoError> {
        let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
        let payload = Payload { msg: input, aad };
        let nonce = Nonce::from([0u8; NONCE_LEN]);
        let result = if encrypt {
            cipher
                .encrypt(&nonce, payload)
                .map_err(|_| CryptoError::Encryption)
        } else {
            cipher
                .decrypt(&nonce, payload)
                .map_err(|_| CryptoError::AuthenticationFailed)
        };
        result.map(Bytes::from)
    }
}

impl core::fmt::Debug for HandshakeKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HandshakeKeys([REDACTED])")
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
        shared: &SharedSecret,
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