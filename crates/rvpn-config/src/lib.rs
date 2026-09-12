//! TOML configuration parsing and validation for RVPN applications.

use ipnet::IpNet;
pub use rvpn_interface::DeviceMode;
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
        if self.routing.default_route && self.server.is_ipv4() && self.routing.endpoint_gateway.is_none() {
            return Err(ConfigError::Invalid(
                "routing.endpoint_gateway is required for default_route when server endpoint is IPv4",
            ));
        }
        if self.routing.default_route_v6 && self.server.is_ipv6() && self.routing.endpoint_gateway_v6.is_none() {
            return Err(ConfigError::Invalid(
                "routing.endpoint_gateway_v6 is required for default_route_v6 when server endpoint is IPv6",
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
    /// Statically provisioned client identities. When populated, the legacy
    /// top-level PSK is not used for new sessions.
    #[serde(default)]
    pub peers: Vec<ServerPeerConfig>,
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
        if self.peers.is_empty() {
            validate_psk(&self.pre_shared_key)?;
        } else {
            for peer in &self.peers {
                peer.validate()?;
            }
        }
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

    /// Returns provisioned peers, retaining old single-PSK configuration as
    /// one unrestricted compatibility identity.
    pub fn peer_identities(&self) -> Result<Vec<PeerIdentity>, ConfigError> {
        if self.peers.is_empty() {
            return Ok(vec![PeerIdentity {
                name: "legacy".into(),
                pre_shared_key: self.pre_shared_key_bytes()?,
                allowed_ips: Vec::new(),
            }]);
        }
        self.peers.iter().map(ServerPeerConfig::identity).collect()
    }
}

/// One statically provisioned RVPN client on a multi-client server.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ServerPeerConfig {
    pub name: String,
    pub pre_shared_key: String,
    /// Source addresses this peer may inject, and destinations routed to it.
    pub allowed_ips: Vec<String>,
}

impl ServerPeerConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.name.is_empty() || self.allowed_ips.is_empty() {
            return Err(ConfigError::Invalid(
                "each server peer needs a name and at least one allowed_ips prefix",
            ));
        }
        validate_psk(&self.pre_shared_key)?;
        for prefix in &self.allowed_ips {
            prefix.parse::<IpNet>().map_err(|_| {
                ConfigError::Invalid("peer allowed_ips must contain valid CIDR prefixes")
            })?;
        }
        Ok(())
    }

    fn identity(&self) -> Result<PeerIdentity, ConfigError> {
        Ok(PeerIdentity {
            name: self.name.clone(),
            pre_shared_key: decode_psk(&self.pre_shared_key)?,
            allowed_ips: self
                .allowed_ips
                .iter()
                .map(|prefix| prefix.parse())
                .collect::<Result<Vec<IpNet>, _>>()
                .map_err(|_| {
                    ConfigError::Invalid("peer allowed_ips must contain valid CIDR prefixes")
                })?,
        })
    }
}

/// Validated server-side identity used by the application session table.
#[derive(Clone, Debug)]
pub struct PeerIdentity {
    pub name: String,
    pub pre_shared_key: [u8; 32],
    pub allowed_ips: Vec<IpNet>,
}

/// Platform-neutral settings for a local Layer-3/Layer-2 tunnel device.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InterfaceConfig {
    /// Requested interface name; omit it to let Linux choose one.
    pub name: Option<String>,
    /// Secondary TAP interface name when running in `both` mode.
    pub tap_name: Option<String>,
    /// Maximum IP packet size. App transport buffers include protocol overhead.
    pub mtu: Option<u16>,
    /// Operating mode: `tun`, `tap`, or `both`. Defaults to `tun`.
    pub mode: Option<DeviceMode>,
    /// CIDR address assigned to this TUN/TAP device, for example `10.42.0.2/24`.
    pub address: Option<String>,
    /// Additional CIDR addresses; use this for dual-stack interfaces.
    #[serde(default)]
    pub addresses: Vec<String>,
}

impl Default for InterfaceConfig {
    fn default() -> Self {
        Self {
            name: None,
            tap_name: None,
            mtu: None,
            mode: None,
            address: None,
            addresses: Vec::new(),
        }
    }
}

impl InterfaceConfig {
    /// Returns the operating mode (defaults to `DeviceMode::Tun`).
    pub fn mode(&self) -> DeviceMode {
        self.mode.unwrap_or_default()
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
    /// Install an IPv6 default route through the tunnel.
    #[serde(default)]
    pub default_route_v6: bool,
    pub gateway_v6: Option<String>,
    pub endpoint_gateway_v6: Option<String>,
    #[serde(default)]
    pub routes: Vec<String>,
}

impl ClientRoutingConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.default_route && self.gateway.is_none() {
            return Err(ConfigError::Invalid(
                "routing.gateway is required for default_route",
            ));
        }
        if self.default_route_v6 && self.gateway_v6.is_none() {
            return Err(ConfigError::Invalid(
                "routing.gateway_v6 is required for default_route_v6",
            ));
        }
        for route in &self.routes {
            route.parse::<IpNet>().map_err(|_| {
                ConfigError::Invalid("routing.routes must contain valid CIDR prefixes")
            })?;
        }
        Ok(())
    }
}

/// Supported firewall backend implementation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FirewallBackend {
    /// Auto-detect: probe for `nft`, fallback to `iptables`/`ip6tables`.
    #[default]
    Auto,
    /// Use `iptables` and `ip6tables`.
    Iptables,
    /// Use `nft` (nftables).
    Nftables,
}

/// Opt-in Linux forwarding and NAT settings for an internet-facing server.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ForwardingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub backend: FirewallBackend,
    pub external_interface: Option<String>,
    pub tunnel_cidr: Option<String>,
    /// Optional IPv6 tunnel prefix for forwarding and NAT66.
    pub tunnel_cidr_v6: Option<String>,
}

impl ForwardingConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.enabled
            && (self
                .external_interface
                .as_deref()
                .unwrap_or_default()
                .is_empty()
                || (self.tunnel_cidr.as_deref().unwrap_or_default().is_empty()
                    && self
                        .tunnel_cidr_v6
                        .as_deref()
                        .unwrap_or_default()
                        .is_empty()))
        {
            return Err(ConfigError::Invalid(
                "forwarding.external_interface and at least one tunnel CIDR are required when forwarding is enabled",
            ));
        }
        if let Some(cidr) = &self.tunnel_cidr {
            if !matches!(cidr.parse::<IpNet>(), Ok(IpNet::V4(_))) {
                return Err(ConfigError::Invalid(
                    "forwarding.tunnel_cidr must be an IPv4 CIDR",
                ));
            }
        }
        if let Some(cidr) = &self.tunnel_cidr_v6 {
            if !matches!(cidr.parse::<IpNet>(), Ok(IpNet::V6(_))) {
                return Err(ConfigError::Invalid(
                    "forwarding.tunnel_cidr_v6 must be an IPv6 CIDR",
                ));
            }
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
        for address in self.address.iter().chain(&self.addresses) {
            address.parse::<IpNet>().map_err(|_| {
                ConfigError::Invalid("interface addresses must be valid CIDR prefixes")
            })?;
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

    #[test]
    fn parses_provisioned_server_peers() {
        let config = ServerConfig::from_toml(
            "bind = '127.0.0.1:9000'\npre_shared_key = ''\n[[peers]]\nname = 'laptop'\npre_shared_key = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\nallowed_ips = ['10.42.0.2/32']",
        ).unwrap();
        let peers = config.peer_identities().unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].name, "laptop");
    }

    #[test]
    fn parses_tap_and_both_mode_and_firewall() {
        let server_toml = r#"
bind = '0.0.0.0:9000'
pre_shared_key = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'

[interface]
name = 'rvpn-srv'
tap_name = 'rvpn-tap'
mode = 'both'

[forwarding]
enabled = true
backend = 'iptables'
external_interface = 'eth0'
tunnel_cidr = '10.42.0.0/24'
tunnel_cidr_v6 = 'fd42::/64'
"#;
        let config = ServerConfig::from_toml(server_toml).unwrap();
        assert_eq!(config.interface.mode(), DeviceMode::Both);
        assert_eq!(config.forwarding.backend, FirewallBackend::Iptables);

        let client_toml = r#"
server = '10.0.0.91:9000'
pre_shared_key = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'

[interface]
mode = 'tap'

[routing]
default_route = true
gateway = '10.42.0.1'
endpoint_gateway = '192.168.88.1'
default_route_v6 = true
gateway_v6 = 'fd42::1'
"#;
        let client_cfg = ClientConfig::from_toml(client_toml).unwrap();
        assert_eq!(client_cfg.interface.mode(), DeviceMode::Tap);
        assert!(client_cfg.routing.default_route_v6);
    }
}
