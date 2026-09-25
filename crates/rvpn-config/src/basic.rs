use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf};

use crate::ConfigError;
use crate::network::{
    ClientRoutingConfig, ConfigValidation, HandshakeConfig, InterfaceConfig, LivenessConfig,
    RekeyConfig,
};
use crate::util::{decode_certificate, decode_psk, validate_endpoint_syntax};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub endpoint: SocketAddr,
    pub identity_file: Option<PathBuf>,
}

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

    pub fn validate_resolved(&self, _resolved: SocketAddr) -> Result<(), ConfigError> {
        Ok(())
    }

    pub fn auth_config(&self) -> Result<rvpn_crypto::AuthConfig, ConfigError> {
        let auth = self.auth.as_ref().ok_or(ConfigError::Invalid(
            "`auth` is required (mode = \"pinned-key\" or mode = \"certificate\")",
        ))?;
        auth.to_auth_config()
    }

    pub fn obfuscation_key_bytes(&self) -> Result<Option<[u8; 32]>, ConfigError> {
        self.obfuscation_key.as_deref().map(decode_psk).transpose()
    }
}