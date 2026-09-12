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
    /// Bounded retransmission policy for the initial and rekey handshakes.
    #[serde(default)]
    pub handshake: HandshakeConfig,
    /// When to rotate packet-protection keys. Zero disables automatic rekeying.
    #[serde(default)]
    pub rekey: RekeyConfig,
    /// Optional routes installed after the TUN interface is created.
    #[serde(default)]
    pub routing: ClientRoutingConfig,
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
        self.interface
            .validate()
            .and_then(|_| self.handshake.validate())
            .and_then(|_| self.rekey.validate())
            .and_then(|_| self.routing.validate())?;
        if self.routing.default_route && !self.server.is_ipv4() {
            return Err(ConfigError::Invalid(
                "routing.default_route currently supports an IPv4 server endpoint only",
            ));
        }
        Ok(())
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
    #[serde(default)]
    pub handshake: HandshakeConfig,
    #[serde(default)]
    pub rekey: RekeyConfig,
    #[serde(default)]
    pub forwarding: ForwardingConfig,
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
        self.interface
            .validate()
            .and_then(|_| self.handshake.validate())
            .and_then(|_| self.rekey.validate())
            .and_then(|_| self.forwarding.validate())
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
    /// CIDR address assigned to this TUN device, for example `10.42.0.2/24`.
    pub address: Option<String>,
}

impl Default for InterfaceConfig {
    fn default() -> Self {
        Self {
            name: None,
            mtu: None,
            address: None,
        }
    }
}

/// Timeout and retry settings for UDP handshake flights.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HandshakeConfig {
    #[serde(default = "default_retry_interval_ms")]
    pub retry_interval_ms: u64,
    #[serde(default = "default_retry_limit")]
    pub retry_limit: u32,
}

const fn default_retry_interval_ms() -> u64 {
    500
}
const fn default_retry_limit() -> u32 {
    5
}

impl Default for HandshakeConfig {
    fn default() -> Self {
        Self {
            retry_interval_ms: default_retry_interval_ms(),
            retry_limit: default_retry_limit(),
        }
    }
}

impl HandshakeConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.retry_interval_ms == 0 || self.retry_limit == 0 {
            return Err(ConfigError::Invalid(
                "handshake retry interval and limit must be non-zero",
            ));
        }
        Ok(())
    }
}

/// Automatic rekey threshold. A phase is rotated before this many sent packets.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RekeyConfig {
    #[serde(default = "default_rekey_packet_limit")]
    pub packet_limit: u64,
}

const fn default_rekey_packet_limit() -> u64 {
    1 << 20
}

impl Default for RekeyConfig {
    fn default() -> Self {
        Self {
            packet_limit: default_rekey_packet_limit(),
        }
    }
}

impl RekeyConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        Ok(())
    }
}

/// Client route policy, applied only when an interface address is configured.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ClientRoutingConfig {
    #[serde(default)]
    pub default_route: bool,
    pub gateway: Option<String>,
    /// Physical-network next hop used to keep the UDP server endpoint outside
    /// a tunnel-installed default route.
    pub endpoint_gateway: Option<String>,
    #[serde(default)]
    pub routes: Vec<String>,
}

impl ClientRoutingConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.default_route && (self.gateway.is_none() || self.endpoint_gateway.is_none()) {
            return Err(ConfigError::Invalid(
                "routing.gateway and routing.endpoint_gateway are required for default_route",
            ));
        }
        Ok(())
    }
}

/// Opt-in Linux forwarding and NAT settings for an internet-facing server.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ForwardingConfig {
    #[serde(default)]
    pub enabled: bool,
    pub external_interface: Option<String>,
    pub tunnel_cidr: Option<String>,
}

impl ForwardingConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.enabled
            && (self
                .external_interface
                .as_deref()
                .unwrap_or_default()
                .is_empty()
                || self.tunnel_cidr.as_deref().unwrap_or_default().is_empty())
        {
            return Err(ConfigError::Invalid(
                "forwarding.external_interface and forwarding.tunnel_cidr are required when forwarding is enabled",
            ));
        }
        Ok(())
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
