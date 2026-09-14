use crate::CryptoError;
use bytes::{Bytes, BytesMut};
use chacha20::{
    ChaCha20,
    cipher::{KeyIvInit, StreamCipher},
};
use rand::{TryRng, rngs::SysRng};

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const MAX_PADDING: usize = 255;
pub const OBFUSCATION_OVERHEAD: usize = NONCE_LEN + 1 + MAX_PADDING;

pub struct ObfuscationKey([u8; KEY_LEN]);

impl ObfuscationKey {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = [0; KEY_LEN];
        SysRng
            .try_fill_bytes(&mut bytes)
            .map_err(CryptoError::Randomness)?;
        Ok(Self(bytes))
    }

    pub fn wrap(&self, inner: &[u8]) -> Result<Bytes, CryptoError> {
        let mut nonce = [0u8; NONCE_LEN];
        SysRng
            .try_fill_bytes(&mut nonce)
            .map_err(CryptoError::Randomness)?;
        let mut pad_selector = [0u8; 1];
        SysRng
            .try_fill_bytes(&mut pad_selector)
            .map_err(CryptoError::Randomness)?;
        let padding_len = (pad_selector[0] as usize) % (MAX_PADDING + 1);
        let mut padding = vec![0u8; padding_len];
        SysRng
            .try_fill_bytes(&mut padding)
            .map_err(CryptoError::Randomness)?;

        let mut body = Vec::with_capacity(1 + inner.len() + padding_len);
        body.push(padding_len as u8);
        body.extend_from_slice(inner);
        body.extend_from_slice(&padding);

        let mut cipher =
            ChaCha20::new_from_slices(&self.0, &nonce).map_err(|_| CryptoError::InvalidKey)?;
        cipher.apply_keystream(&mut body);

        let mut output = BytesMut::with_capacity(NONCE_LEN + body.len());
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&body);
        Ok(output.freeze())
    }

    pub fn unwrap(&self, datagram: &[u8]) -> Result<Bytes, CryptoError> {
        if datagram.len() < NONCE_LEN + 1 {
            return Err(CryptoError::ObfuscationTooShort);
        }
        let (nonce, body) = datagram.split_at(NONCE_LEN);
        let mut body = body.to_vec();
        let mut cipher =
            ChaCha20::new_from_slices(&self.0, nonce).map_err(|_| CryptoError::InvalidKey)?;
        cipher.apply_keystream(&mut body);

        let padding_len = body[0] as usize;
        if body.len() < 1 + padding_len {
            return Err(CryptoError::ObfuscationTooShort);
        }
        let inner_end = body.len() - padding_len;
        Ok(Bytes::copy_from_slice(&body[1..inner_end]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_varies_ciphertext_per_call() {
        let key = ObfuscationKey::from_bytes([9; 32]);
        let a = key.wrap(b"handshake bytes").unwrap();
        let b = key.wrap(b"handshake bytes").unwrap();
        assert_ne!(a, b, "nonce and padding must vary per call");
        assert_eq!(key.unwrap(&a).unwrap(), b"handshake bytes"[..]);
        assert_eq!(key.unwrap(&b).unwrap(), b"handshake bytes"[..]);
    }

    #[test]
    fn rejects_undersized_datagrams() {
        let key = ObfuscationKey::from_bytes([1; 32]);
        assert!(matches!(
            key.unwrap(&[0; 5]),
            Err(CryptoError::ObfuscationTooShort)
        ));
    }
}
