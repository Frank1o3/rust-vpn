//! Established cryptographic building blocks for RVPN.
//!
//! This foundation uses ephemeral X25519, HKDF-SHA-256, and
//! ChaCha20-Poly1305. It does not yet authenticate peers: a future protocol
//! handshake must bind identities and the exact transcript before key use.

use bytes::Bytes;
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{TryRng, rngs::SysRng};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const INFO_C2S: &[u8] = b"rvpn-v1/session/client-to-server";
const INFO_S2C: &[u8] = b"rvpn-v1/session/server-to-client";
const PSK_LEN: usize = 32;

/// Memory-cleared secret bytes.
pub struct Secret<const N: usize>([u8; N]);

impl<const N: usize> Secret<N> {
    /// Obtains secret bytes from the operating system's cryptographic RNG.
    pub fn random() -> Result<Self, CryptoError> {
        let mut bytes = [0; N];
        SysRng
            .try_fill_bytes(&mut bytes)
            .map_err(CryptoError::Randomness)?;
        Ok(Self(bytes))
    }

    fn from_bytes(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }
}

/// Generates non-secret random protocol bytes from the operating-system CSPRNG.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    Ok(Secret::<N>::random()?.0)
}

/// Computes the SHA-256 transcript hash supplied to session-key derivation.
pub fn transcript_hash(transcript: &[u8]) -> [u8; KEY_LEN] {
    Sha256::digest(transcript).into()
}

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<const N: usize> core::fmt::Debug for Secret<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}

/// Public X25519 key bytes for protocol serialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicKeyBytes([u8; KEY_LEN]);

impl PublicKeyBytes {
    /// Creates a public key representation from 32 wire bytes.
    pub const fn new(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the wire representation.
    pub const fn to_bytes(self) -> [u8; KEY_LEN] {
        self.0
    }
}

/// A one-use ephemeral X25519 key pair.
pub struct EphemeralKeyPair {
    // StaticSecret permits construction from caller-supplied OS randomness.
    // This wrapper consumes it in `agree`, preserving one-use semantics.
    secret: StaticSecret,
    public: PublicKeyBytes,
}

impl EphemeralKeyPair {
    /// Generates a fresh ephemeral key pair.
    pub fn generate() -> Result<Self, CryptoError> {
        let bytes = Secret::<KEY_LEN>::random()?.0;
        let secret = StaticSecret::from(bytes);
        let public = PublicKeyBytes::new(PublicKey::from(&secret).to_bytes());
        Ok(Self { secret, public })
    }

    /// Returns the public half of this key pair.
    pub const fn public_key(&self) -> PublicKeyBytes {
        self.public
    }

    /// Consumes the private key to calculate a shared secret with `peer`.
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

/// X25519 shared secret, intentionally usable only for key derivation.
pub struct SharedSecret(Secret<KEY_LEN>);

impl core::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SharedSecret([REDACTED])")
    }
}

/// A 256-bit pre-shared key used to authenticate the initial RVPN handshake.
///
/// This is a bootstrap authentication mechanism for the first client/server
/// implementation. A later identity system may replace it without changing
/// the X25519, HKDF, or packet-AEAD boundaries.
pub struct HandshakePsk(Secret<PSK_LEN>);

impl HandshakePsk {
    /// Constructs a PSK from securely provisioned 32-byte key material.
    pub fn from_bytes(bytes: [u8; PSK_LEN]) -> Self {
        Self(Secret::from_bytes(bytes))
    }

    /// Generates a fresh PSK for secure out-of-band provisioning.
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self(Secret::random()?))
    }

    /// Computes a 32-byte HMAC-SHA-256 over canonical handshake data.
    pub fn authenticate(&self, data: &[u8]) -> [u8; PSK_LEN] {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.0.as_bytes())
            .expect("fixed-length HMAC keys are always accepted");
        mac.update(data);
        mac.finalize().into_bytes().into()
    }

    /// Verifies a handshake authenticator in constant time.
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

/// Session side used to assign directional key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionRole {
    Initiator,
    Responder,
}

/// Directional session keys for one protocol key phase.
pub struct SessionKeys {
    send: Secret<KEY_LEN>,
    receive: Secret<KEY_LEN>,
}

impl SessionKeys {
    /// Derives directional keys bound to an authenticated handshake transcript.
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

    /// Encrypts a payload and authenticates its protocol header as AAD.
    pub fn seal(
        &self,
        nonce: PacketNonce,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Bytes, CryptoError> {
        crypt(true, self.send.as_bytes(), nonce, aad, plaintext)
    }

    /// Verifies AAD and decrypts a payload.
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

/// A deterministic AEAD nonce built from a unique key phase and packet sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketNonce([u8; NONCE_LEN]);

impl PacketNonce {
    /// Builds a nonce. The caller must never repeat this pair for one key.
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

/// Cryptographic failures without exposing sensitive material.
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peers_derive_opposite_directional_keys_and_round_trip() {
        let initiator = EphemeralKeyPair::generate().unwrap();
        let responder = EphemeralKeyPair::generate().unwrap();
        let initiator_public = initiator.public_key();
        let responder_public = responder.public_key();
        let initiator_secret = initiator.agree(responder_public).unwrap();
        let responder_secret = responder.agree(initiator_public).unwrap();
        let send = SessionKeys::derive(initiator_secret, &[7; 32], SessionRole::Initiator).unwrap();
        let receive =
            SessionKeys::derive(responder_secret, &[7; 32], SessionRole::Responder).unwrap();
        let nonce = PacketNonce::from_sequence(0, 1);
        let encrypted = send.seal(nonce, b"header", b"message").unwrap();
        assert_eq!(
            receive.open(nonce, b"header", &encrypted).unwrap(),
            b"message"[..]
        );
    }

    #[test]
    fn authentication_binds_header_and_nonce_inputs_differ() {
        let initiator = EphemeralKeyPair::generate().unwrap();
        let responder = EphemeralKeyPair::generate().unwrap();
        let initiator_public = initiator.public_key();
        let responder_public = responder.public_key();
        let send = SessionKeys::derive(
            initiator.agree(responder_public).unwrap(),
            &[3; 32],
            SessionRole::Initiator,
        )
        .unwrap();
        let receive = SessionKeys::derive(
            responder.agree(initiator_public).unwrap(),
            &[3; 32],
            SessionRole::Responder,
        )
        .unwrap();
        let ciphertext = send
            .seal(PacketNonce::from_sequence(1, 9), b"a", b"message")
            .unwrap();
        assert!(matches!(
            receive.open(PacketNonce::from_sequence(1, 9), b"b", &ciphertext),
            Err(CryptoError::AuthenticationFailed)
        ));
        assert_ne!(
            PacketNonce::from_sequence(1, 9),
            PacketNonce::from_sequence(1, 10)
        );
    }
}
