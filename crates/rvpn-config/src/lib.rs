//! TOML configuration parsing and validation for RVPN applications.

use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf};
use thiserror::Error;

/// Common configuration accepted by RVPN applications.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    /// UDP address to bind or contact, depending on the application.
    pub endpoint: SocketAddr,
    /// Optional path to a future persistent identity or key configuration.
    pub identity_file: Option<PathBuf>,
}

impl Config {
    /// Parses and validates TOML configuration.
    pub fn from_toml(input: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(input).map_err(ConfigError::Parse)?;
        config.validate()?;
        Ok(config)
    }

    /// Validates configuration invariants independent of parsing.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.endpoint.port() == 0 {
            return Err(ConfigError::Invalid("endpoint port must not be zero"));
        }
        Ok(())
    }
}

/// Client configuration for the initial authenticated UDP handshake.
#[derive(Clone, Deserialize, Serialize)]
pub struct ClientConfig {
    /// RVPN server UDP endpoint.
    pub server: SocketAddr,
    /// Exactly 32 random bytes encoded as 64 hexadecimal characters.
    pub pre_shared_key: String,
    /// Local TUN device settings used after session establishment.
    #[serde(default)]
    pub interface: InterfaceConfig,
}

impl ClientConfig {
    /// Parses and validates client TOML.
    pub fn from_toml(input: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(input).map_err(ConfigError::Parse)?;
        config.validate()?;
        Ok(config)
    }

    /// Checks endpoint and PSK encoding without logging secret material.
    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_endpoint(self.server)?;
        validate_psk(&self.pre_shared_key)?;
        self.interface.validate()
    }

    /// Decodes the provisioned PSK for handoff to the crypto layer.
    pub fn pre_shared_key_bytes(&self) -> Result<[u8; 32], ConfigError> {
        decode_psk(&self.pre_shared_key)
    }
}

/// Server configuration for the initial authenticated UDP handshake.
#[derive(Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    /// Static UDP address on which the server listens.
    pub bind: SocketAddr,
    /// Exactly 32 random bytes encoded as 64 hexadecimal characters.
    pub pre_shared_key: String,
    /// Local TUN device settings used after session establishment.
    #[serde(default)]
    pub interface: InterfaceConfig,
}

impl ServerConfig {
    /// Parses and validates server TOML.
    pub fn from_toml(input: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(input).map_err(ConfigError::Parse)?;
        config.validate()?;
        Ok(config)
    }

    /// Checks bind endpoint and PSK encoding.
    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_endpoint(self.bind)?;
        validate_psk(&self.pre_shared_key)?;
        self.interface.validate()
    }

    /// Decodes the provisioned PSK for handoff to the crypto layer.
    pub fn pre_shared_key_bytes(&self) -> Result<[u8; 32], ConfigError> {
        decode_psk(&self.pre_shared_key)
    }
}

/// Platform-neutral settings for a local Layer-3 tunnel device.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InterfaceConfig {
    /// Requested interface name; omit it to let Linux choose one.
    pub name: Option<String>,
    /// Maximum IP packet size. App transport buffers include protocol overhead.
    pub mtu: Option<u16>,
}

impl Default for InterfaceConfig {
    fn default() -> Self {
        Self {
            name: None,
            mtu: None,
        }
    }
}

impl InterfaceConfig {
    /// Rejects an obviously unusable configured IP MTU.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if matches!(self.mtu, Some(mtu) if mtu < 576) {
            return Err(ConfigError::Invalid("interface MTU must be at least 576"));
        }
        Ok(())
    }
}

fn validate_endpoint(endpoint: SocketAddr) -> Result<(), ConfigError> {
    if endpoint.port() == 0 {
        return Err(ConfigError::Invalid("endpoint port must not be zero"));
    }
    Ok(())
}

fn validate_psk(value: &str) -> Result<(), ConfigError> {
    decode_psk(value).map(|_| ())
}

fn decode_psk(value: &str) -> Result<[u8; 32], ConfigError> {
    if value.len() != 64 {
        return Err(ConfigError::InvalidPreSharedKey);
    }
    let mut bytes = [0; 32];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| ConfigError::InvalidPreSharedKey)?;
    Ok(bytes)
}

/// Configuration parsing and validation errors.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid TOML configuration: {0}")]
    Parse(#[source] toml::de::Error),
    #[error("invalid configuration: {0}")]
    Invalid(&'static str),
    #[error("pre_shared_key must be exactly 32 bytes encoded as hexadecimal")]
    InvalidPreSharedKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_toml() {
        let config = Config::from_toml("endpoint = '127.0.0.1:9000'").unwrap();
        assert_eq!(config.endpoint.port(), 9000);
    }

    #[test]
    fn validates_client_psk_without_exposing_it() {
        let config = ClientConfig::from_toml(
            "server = '127.0.0.1:9000'\npre_shared_key = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'",
        ).unwrap();
        assert_eq!(config.pre_shared_key_bytes().unwrap(), [0xaa; 32]);
        assert!(
            ClientConfig::from_toml("server = '127.0.0.1:9000'\npre_shared_key = 'bad'").is_err()
        );
    }
}
