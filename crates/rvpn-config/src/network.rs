use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, time::Duration};

use crate::ConfigError;
pub use rvpn_interface::DeviceMode;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceConfig {
    pub name: Option<String>,
    pub tap_name: Option<String>,
    pub mtu: Option<u16>,
    pub mode: Option<DeviceMode>,
    pub address: Option<String>,
    #[serde(default)]
    pub addresses: Vec<String>,
    pub dns_servers: Option<String>,
}

impl InterfaceConfig {
    pub fn mode(&self) -> DeviceMode {
        self.mode.unwrap_or_default()
    }

    /// Parsed `dns_servers`, empty when unset.
    pub fn dns_server_list(&self) -> Result<Vec<IpAddr>, ConfigError> {
        let Some(raw) = self.dns_servers.as_deref() else {
            return Ok(Vec::new());
        };
        raw.split(|c: char| c == ',' || c.is_whitespace())
            .filter(|part| !part.is_empty())
            .map(|part| {
                part.parse::<IpAddr>().map_err(|_| {
                    ConfigError::Invalid(
                        "interface.dns_servers must be a comma-separated list of IP addresses",
                    )
                })
            })
            .collect()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HandshakeConfig {
    #[serde(default = "default_retry_interval_ms")]
    pub retry_interval_ms: u64,
    #[serde(default = "default_retry_limit")]
    pub retry_limit: u32,
    #[serde(default = "default_retry_jitter_ms")]
    pub retry_jitter_ms: u64,
}

const fn default_retry_jitter_ms() -> u64 {
    150
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
            retry_jitter_ms: default_retry_jitter_ms(),
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RekeyConfig {
    #[serde(default = "default_rekey_packet_limit")]
    pub packet_limit: u64,
    #[serde(default = "default_rekey_time_limit_secs")]
    pub time_limit_secs: u64,
}

const fn default_rekey_packet_limit() -> u64 {
    1 << 20
}

const fn default_rekey_time_limit_secs() -> u64 {
    120
}

impl Default for RekeyConfig {
    fn default() -> Self {
        Self {
            packet_limit: default_rekey_packet_limit(),
            time_limit_secs: default_rekey_time_limit_secs(),
        }
    }
}

impl RekeyConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        Ok(())
    }

    pub fn time_limit(&self) -> Option<Duration> {
        if self.time_limit_secs == 0 {
            None
        } else {
            Some(Duration::from_secs(self.time_limit_secs))
        }
    }
}

/// Dead-peer detection. Keepalives are sent roughly every 25 seconds, so the
/// timeout must leave room for several missed ones.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LivenessConfig {
    /// Seconds without any authenticated packet before the peer is considered
    /// gone: the server drops the session, the client reconnects. `0` disables.
    #[serde(default = "default_liveness_timeout_secs")]
    pub timeout_secs: u64,
}

const fn default_liveness_timeout_secs() -> u64 {
    90
}

impl Default for LivenessConfig {
    fn default() -> Self {
        Self {
            timeout_secs: default_liveness_timeout_secs(),
        }
    }
}

impl LivenessConfig {
    pub fn timeout(&self) -> Option<Duration> {
        (self.timeout_secs != 0).then(|| Duration::from_secs(self.timeout_secs))
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.timeout_secs != 0 && self.timeout_secs < 60 {
            return Err(ConfigError::Invalid(
                "liveness.timeout_secs must be 0 (disabled) or at least 60",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientRoutingConfig {
    #[serde(default)]
    pub default_route: bool,
    pub gateway: Option<String>,
    /// Accepted for backward compatibility and ignored: the route to the
    /// server is taken from the OS routing table when connecting.
    pub endpoint_gateway: Option<String>,
    #[serde(default)]
    pub default_route_v6: bool,
    pub gateway_v6: Option<String>,
    /// Accepted for backward compatibility and ignored.
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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FirewallBackend {
    #[default]
    Auto,
    Iptables,
    Nftables,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub backend: FirewallBackend,
    pub external_interface: Option<String>,
    pub tunnel_cidr: Option<String>,
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
        if let Some(cidr) = &self.tunnel_cidr
            && !matches!(cidr.parse::<IpNet>(), Ok(IpNet::V4(_)))
        {
            return Err(ConfigError::Invalid(
                "forwarding.tunnel_cidr must be an IPv4 CIDR",
            ));
        }

        if let Some(cidr) = &self.tunnel_cidr_v6
            && !matches!(cidr.parse::<IpNet>(), Ok(IpNet::V6(_)))
        {
            return Err(ConfigError::Invalid(
                "forwarding.tunnel_cidr_v6 must be an IPv6 CIDR",
            ));
        }
        Ok(())
    }
}

impl InterfaceConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if matches!(self.mtu, Some(mtu) if mtu < 576) {
            return Err(ConfigError::Invalid("interface MTU must be at least 576"));
        }
        for address in self.address.iter().chain(&self.addresses) {
            address.parse::<IpNet>().map_err(|_| {
                ConfigError::Invalid("interface addresses must be valid CIDR prefixes")
            })?;
        }
        self.dns_server_list()?;
        Ok(())
    }
}

pub(crate) trait ConfigValidation {
    fn validate(&self) -> Result<(), ConfigError>;
}

impl ConfigValidation for HandshakeConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        HandshakeConfig::validate(self)
    }
}

impl ConfigValidation for RekeyConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        RekeyConfig::validate(self)
    }
}

impl ConfigValidation for LivenessConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        LivenessConfig::validate(self)
    }
}

impl ConfigValidation for ClientRoutingConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        ClientRoutingConfig::validate(self)
    }
}

impl ConfigValidation for ForwardingConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        ForwardingConfig::validate(self)
    }
}

impl ConfigValidation for InterfaceConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        InterfaceConfig::validate(self)
    }
}
