//! Long-term Ed25519 identity keys and short-lived certificates, for
//! certificate-based peer authentication as an alternative to a PSK.

use crate::{CryptoError, Secret};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

const SEED_LEN: usize = 32;
const SIG_LEN: usize = 64;
/// subject_pubkey(32) + not_before(8) + not_after(8) + issuer_signature(64)
const CERT_LEN: usize = 32 + 8 + 8 + 64;

/// A long-term Ed25519 signing identity for a peer or a certificate authority.
pub struct IdentityKeyPair {
    signing: SigningKey,
}

impl IdentityKeyPair {
    /// Generates a fresh identity key.
    pub fn generate() -> Result<Self, CryptoError> {
        let seed = Secret::<SEED_LEN>::random()?.0;
        Ok(Self {
            signing: SigningKey::from_bytes(&seed),
        })
    }

    /// Restores an identity key from a securely provisioned 32-byte seed.
    pub fn from_seed(seed: [u8; SEED_LEN]) -> Self {
        Self {
            signing: SigningKey::from_bytes(&seed),
        }
    }

    /// Returns the public half for distribution to peers.
    pub fn public_key(&self) -> IdentityPublicKey {
        IdentityPublicKey(self.signing.verifying_key().to_bytes())
    }

    /// Signs arbitrary transcript bytes with this identity.
    pub fn sign(&self, message: &[u8]) -> [u8; SIG_LEN] {
        self.signing.sign(message).to_bytes()
    }

    /// Issues a certificate binding `subject` for the given Unix-second
    /// validity window, signed by this key acting as issuer/CA.
    pub fn issue_certificate(
        &self,
        subject: IdentityPublicKey,
        not_before: u64,
        not_after: u64,
    ) -> Certificate {
        let signature = self.sign(&signed_fields(subject, not_before, not_after));
        Certificate {
            subject,
            not_before,
            not_after,
            issuer_signature: signature,
        }
    }
}

impl core::fmt::Debug for IdentityKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("IdentityKeyPair([REDACTED])")
    }
}

fn signed_fields(subject: IdentityPublicKey, not_before: u64, not_after: u64) -> [u8; 48] {
    let mut signed = [0u8; 48];
    signed[..32].copy_from_slice(&subject.0);
    signed[32..40].copy_from_slice(&not_before.to_be_bytes());
    signed[40..].copy_from_slice(&not_after.to_be_bytes());
    signed
}

/// Wire-format Ed25519 public key for a peer or certificate authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdentityPublicKey([u8; 32]);

impl IdentityPublicKey {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    fn verifying_key(&self) -> Result<VerifyingKey, CryptoError> {
        VerifyingKey::from_bytes(&self.0).map_err(|_| CryptoError::InvalidIdentityKey)
    }

    /// Verifies a signature over `message` under this public key.
    pub fn verify(&self, message: &[u8], signature: &[u8; SIG_LEN]) -> bool {
        let Ok(key) = self.verifying_key() else {
            return false;
        };
        key.verify(message, &Signature::from_bytes(signature))
            .is_ok()
    }
}

/// A short-lived binding of a subject's identity key, signed by a CA.
#[derive(Clone, Copy, Debug)]
pub struct Certificate {
    pub subject: IdentityPublicKey,
    pub not_before: u64,
    pub not_after: u64,
    pub issuer_signature: [u8; SIG_LEN],
}

impl Certificate {
    pub fn encode(&self) -> [u8; CERT_LEN] {
        let mut bytes = [0u8; CERT_LEN];
        bytes[..32].copy_from_slice(&self.subject.0);
        bytes[32..40].copy_from_slice(&self.not_before.to_be_bytes());
        bytes[40..48].copy_from_slice(&self.not_after.to_be_bytes());
        bytes[48..].copy_from_slice(&self.issuer_signature);
        bytes
    }

    pub fn decode(bytes: &[u8; CERT_LEN]) -> Self {
        let mut subject = [0u8; 32];
        subject.copy_from_slice(&bytes[..32]);
        let mut issuer_signature = [0u8; SIG_LEN];
        issuer_signature.copy_from_slice(&bytes[48..]);
        Self {
            subject: IdentityPublicKey(subject),
            not_before: u64::from_be_bytes(bytes[32..40].try_into().unwrap()),
            not_after: u64::from_be_bytes(bytes[40..48].try_into().unwrap()),
            issuer_signature,
        }
    }

    /// Verifies this certificate was issued by `ca` and is valid at `now`
    /// (Unix seconds).
    pub fn verify(&self, ca: &IdentityPublicKey, now: u64) -> bool {
        if now < self.not_before || now > self.not_after {
            return false;
        }
        ca.verify(
            &signed_fields(self.subject, self.not_before, self.not_after),
            &self.issuer_signature,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn issued_certificate_verifies_under_ca_and_rejects_wrong_ca() {
        let ca = IdentityKeyPair::generate().unwrap();
        let other_ca = IdentityKeyPair::generate().unwrap();
        let peer = IdentityKeyPair::generate().unwrap();
        let cert = ca.issue_certificate(peer.public_key(), now() - 60, now() + 3600);
        assert!(cert.verify(&ca.public_key(), now()));
        assert!(!cert.verify(&other_ca.public_key(), now()));
    }

    #[test]
    fn expired_certificate_is_rejected() {
        let ca = IdentityKeyPair::generate().unwrap();
        let peer = IdentityKeyPair::generate().unwrap();
        let cert = ca.issue_certificate(peer.public_key(), now() - 7200, now() - 3600);
        assert!(!cert.verify(&ca.public_key(), now()));
    }

    #[test]
    fn peer_signature_under_its_own_key_verifies() {
        let peer = IdentityKeyPair::generate().unwrap();
        let sig = peer.sign(b"transcript bytes");
        assert!(peer.public_key().verify(b"transcript bytes", &sig));
        assert!(!peer.public_key().verify(b"tampered", &sig));
    }
}
