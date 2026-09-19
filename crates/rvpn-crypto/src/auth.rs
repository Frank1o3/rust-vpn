use crate::{Certificate, HandshakePsk, IdentityKeyPair, IdentityPublicKey};

#[derive(Clone)]
pub enum AuthConfig {
    Psk([u8; 32]),
    PinnedKey {
        local_seed: [u8; 32],
        peer_public_key: [u8; 32],
    },
    Certificate {
        local_seed: [u8; 32],
        local_certificate: [u8; 112],
        ca_public_key: [u8; 32],
    },
}

impl AuthConfig {
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

impl zeroize::Zeroize for AuthConfig {
    fn zeroize(&mut self) {
        match self {
            Self::Psk(bytes) => bytes.zeroize(),
            Self::PinnedKey {
                local_seed,
                peer_public_key,
            } => {
                local_seed.zeroize();
                peer_public_key.zeroize();
            }
            Self::Certificate {
                local_seed,
                local_certificate,
                ca_public_key,
            } => {
                local_seed.zeroize();
                local_certificate.zeroize();
                ca_public_key.zeroize();
            }
        }
    }
}

impl Drop for AuthConfig {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.zeroize();
    }
}

pub enum AuthIdentity {
    Psk(HandshakePsk),
    PinnedKey(IdentityKeyPair),
    Certificate {
        local_key: IdentityKeyPair,
        certificate: Certificate,
    },
}

pub enum AuthVerifier {
    Psk(HandshakePsk),
    PinnedKey(IdentityPublicKey),
    Certificate(IdentityPublicKey),
}
