//! Peer authentication modes for the RVPN handshake: pre-shared key, a
//! pinned long-term public key, or a certificate issued by a trusted CA.
//!
//! `AuthConfig` is the cloneable, at-rest representation held in
//! configuration. Each handshake attempt derives a fresh `AuthIdentity`
//! (proves the local endpoint) and `AuthVerifier` (checks the remote
//! endpoint) from it -- kept separate because those wrap secret material
//! that deliberately does not implement `Clone`.

use crate::{Certificate, HandshakePsk, IdentityKeyPair, IdentityPublicKey};

/// At-rest authentication configuration for one peer or CA trust relationship.
#[derive(Clone)]
pub enum AuthConfig {
    /// Symmetric pre-shared key, used identically for both directions.
    Psk([u8; 32]),
    /// Both sides sign with a long-term key; each pins the other's public key.
    PinnedKey {
        local_seed: [u8; 32],
        peer_public_key: [u8; 32],
    },
    /// Both sides sign with a long-term key; each side's key is authenticated
    /// via a certificate issued by a trusted CA, rather than pinned directly.
    Certificate {
        local_seed: [u8; 32],
        /// This endpoint's certificate, proving `local_seed`'s public key,
        /// as issued by the CA behind `ca_public_key`.
        local_certificate: [u8; 112],
        ca_public_key: [u8; 32],
    },
}

impl AuthConfig {
    /// Builds the identity used to authenticate this endpoint's own messages.
    pub fn identity(&self) -> AuthIdentity {
        match self {
            Self::Psk(bytes) => AuthIdentity::Psk(HandshakePsk::from_bytes(*bytes)),
            Self::PinnedKey { local_seed, .. } => {
                AuthIdentity::PinnedKey(IdentityKeyPair::from_seed(*local_seed))
            }
            Self::Certificate {
                local_seed,
                local_certificate,
                ..
            } => AuthIdentity::Certificate {
                local_key: IdentityKeyPair::from_seed(*local_seed),
                certificate: Certificate::decode(local_certificate),
            },
        }
    }

    /// Builds the verifier used to check the remote endpoint's messages.
    pub fn verifier(&self) -> AuthVerifier {
        match self {
            Self::Psk(bytes) => AuthVerifier::Psk(HandshakePsk::from_bytes(*bytes)),
            Self::PinnedKey {
                peer_public_key, ..
            } => AuthVerifier::PinnedKey(IdentityPublicKey::new(*peer_public_key)),
            Self::Certificate { ca_public_key, .. } => {
                AuthVerifier::Certificate(IdentityPublicKey::new(*ca_public_key))
            }
        }
    }
}

impl core::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Psk(_) => f.write_str("AuthConfig::Psk([REDACTED])"),
            Self::PinnedKey { .. } => f.write_str("AuthConfig::PinnedKey([REDACTED])"),
            Self::Certificate { .. } => f.write_str("AuthConfig::Certificate([REDACTED])"),
        }
    }
}

/// Material used to prove the local endpoint's identity in one handshake.
pub enum AuthIdentity {
    Psk(HandshakePsk),
    PinnedKey(IdentityKeyPair),
    Certificate {
        local_key: IdentityKeyPair,
        certificate: Certificate,
    },
}

/// Material used to check the remote endpoint's identity in one handshake.
pub enum AuthVerifier {
    Psk(HandshakePsk),
    PinnedKey(IdentityPublicKey),
    Certificate(IdentityPublicKey),
}
