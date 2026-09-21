use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf};

use crate::util::{decode_certificate, decode_psk};
use crate::network::ConfigValidation;
use crate::ConfigError;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub endpoint: SocketAddr,
    pub identity_file: Option<PathBuf>,
}

/// A peer-to-peer link group: every peer named in `between` may exchange
/// traffic with every other peer in the same group. Symmetric by construction.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinkConfig {
    pub between: Vec<String>,
}

impl Config {
    pub fn from_toml(input: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(input).map_err(ConfigError::Parse)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.endpoint.port() == 0 {
            return Err(ConfigError::Invalid("endpoint port must not be zero"));
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "mode", rename_all = "kebab-case")]
pub enum AuthMode {
    Psk {
        pre_shared_key: String,
    },
    PinnedKey {
        local_identity_seed: String,
        peer_public_key: String,
    },
    Certificate {
        local_identity_seed: String,
        local_certificate: String,
        ca_public_key: String,
    },
}

impl AuthMode {
    pub fn to_auth_config(&self) -> Result<rvpn_crypto::AuthConfig, ConfigError> {
        Ok(match self {
            Self::Psk { pre_shared_key } => {
                rvpn_crypto::AuthConfig::Psk(decode_psk(pre_shared_key)?)
            }
            Self::PinnedKey {
                local_identity_seed,
                peer_public_key,
            } => rvpn_crypto::AuthConfig::PinnedKey {
                local_seed: decode_psk(local_identity_seed)?,
                peer_public_key: decode_psk(peer_public_key)?,
            },
            Self::Certificate {
                local_identity_seed,
                local_certificate,
                ca_public_key,
            } => rvpn_crypto::AuthConfig::Certificate {
                local_seed: decode_psk(local_identity_seed)?,
                local_certificate: decode_certificate(local_certificate)?,
                ca_public_key: decode_psk(ca_public_key)?,
            },
        })
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub server: String,
    pub pre_shared_key: Option<String>,
    pub auth: Option<AuthMode>,
    #[serde(default)]
    pub interface: InterfaceConfig,
    #[serde(default)]
    pub handshake: HandshakeConfig,
    #[serde(default)]
    pub rekey: RekeyConfig,
    #[serde(default)]
    pub routing: ClientRoutingConfig,
    #[serde(default)]
    pub liveness: LivenessConfig,
    pub obfuscation_key: Option<String>,
}

impl ClientConfig {
    pub fn from_toml(input: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(input).map_err(ConfigError::Parse)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_endpoint_syntax(&self.server)?;
        self.auth_config()?;
        self.interface
            .validate()
            .and_then(|_| self.handshake.validate())
            .and_then(|_| self.rekey.validate())
            .and_then(|_| self.routing.validate())
            .and_then(|_| self.liveness.validate())?;
        Ok(())
    }

    /// Kept for API compatibility. The server's physical route is discovered
    /// from the OS routing table at connect time, so `routing.endpoint_gateway`
    /// is no longer required (it is still accepted and ignored).
    pub fn validate_resolved(&self, _resolved: SocketAddr) -> Result<(), ConfigError> {
        Ok(())
    }

    pub fn auth_config(&self) -> Result<rvpn_crypto::AuthConfig, ConfigError> {
        if let Some(auth) = &self.auth {
            return auth.to_auth_config();
        }
        let psk = self.pre_shared_key.as_deref().ok_or(ConfigError::Invalid(
            "either `auth` or the legacy `pre_shared_key` must be set",
        ))?;
        Ok(rvpn_crypto::AuthConfig::Psk(decode_psk(psk)?))
    }

    pub fn obfuscation_key_bytes(&self) -> Result<Option<[u8; 32]>, ConfigError> {
        self.obfuscation_key.as_deref().map(decode_psk).transpose()
    }
}

