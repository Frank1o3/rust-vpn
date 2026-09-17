use ipnet::IpNet;
pub use rvpn_interface::DeviceMode;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr, path::PathBuf};
use thiserror::Error;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub endpoint: SocketAddr,
    pub identity_file: Option<PathBuf>,
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
            .and_then(|_| self.routing.validate())?;
        Ok(())
    }

    pub fn validate_resolved(&self, resolved: SocketAddr) -> Result<(), ConfigError> {
        if self.routing.default_route
            && resolved.is_ipv4()
            && self.routing.endpoint_gateway.is_none()
        {
            return Err(ConfigError::Invalid(
                "routing.endpoint_gateway is required for default_route when the resolved server endpoint is IPv4",
            ));
        }
        if self.routing.default_route_v6
            && resolved.is_ipv6()
            && self.routing.endpoint_gateway_v6.is_none()
        {
            return Err(ConfigError::Invalid(
                "routing.endpoint_gateway_v6 is required for default_route_v6 when the resolved server endpoint is IPv6",
            ));
        }
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

pub async fn resolve_endpoint(value: &str) -> Result<SocketAddr, ConfigError> {
    let mut addrs =
        tokio::net::lookup_host(value)
            .await
            .map_err(|source| ConfigError::Resolution {
                host: value.to_string(),
                source,
            })?;
    addrs
        .next()
        .ok_or_else(|| ConfigError::NoResolvedAddress(value.to_string()))
}

pub fn validate_endpoint_syntax(value: &str) -> Result<(), ConfigError> {
    let (_, port_str) = value.rsplit_once(':').ok_or(ConfigError::Invalid(
        "server endpoint must be in host:port or ip:port form",
    ))?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| ConfigError::Invalid("server endpoint port must be a valid number"))?;
    if port == 0 {
        return Err(ConfigError::Invalid(
            "server endpoint port must not be zero",
        ));
    }
    Ok(())
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub bind: SocketAddr,
    pub pre_shared_key: Option<String>,
    #[serde(default)]
    pub peers: Vec<ServerPeerConfig>,
    pub certificate_authority: Option<CertificateAuthorityConfig>,
    #[serde(default)]
    pub interface: InterfaceConfig,
    #[serde(default)]
    pub handshake: HandshakeConfig,
    #[serde(default)]
    pub rekey: RekeyConfig,
    #[serde(default)]
    pub forwarding: ForwardingConfig,
    pub obfuscation_key: Option<String>,
}

impl ServerConfig {
    pub fn from_toml(input: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(input).map_err(ConfigError::Parse)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_endpoint(self.bind)?;
        if self.peers.is_empty() && self.certificate_authority.is_none() {
            let psk = self.pre_shared_key.as_deref().ok_or(ConfigError::Invalid(
                "server needs `peers`, `certificate_authority`, or the legacy `pre_shared_key`",
            ))?;
            validate_psk(psk)?;
        } else {
            for peer in &self.peers {
                peer.validate()?;
            }
            if let Some(ca) = &self.certificate_authority {
                ca.validate()?;
            }
        }
        self.interface
            .validate()
            .and_then(|_| self.handshake.validate())
            .and_then(|_| self.rekey.validate())
            .and_then(|_| self.forwarding.validate())
    }

    pub fn obfuscation_key_bytes(&self) -> Result<Option<[u8; 32]>, ConfigError> {
        self.obfuscation_key.as_deref().map(decode_psk).transpose()
    }

    pub fn peer_identities(&self) -> Result<Vec<PeerIdentity>, ConfigError> {
        if !self.peers.is_empty() {
            return self.peers.iter().map(ServerPeerConfig::identity).collect();
        }
        if self.certificate_authority.is_some() {
            return Ok(Vec::new());
        }
        let psk = self.pre_shared_key.as_deref().ok_or(ConfigError::Invalid(
            "server needs `peers`, `certificate_authority`, or the legacy `pre_shared_key`",
        ))?;
        Ok(vec![PeerIdentity {
            name: "legacy".into(),
            allowed_ips: Vec::new(),
            auth: rvpn_crypto::AuthConfig::Psk(decode_psk(psk)?),
        }])
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ServerPeerConfig {
    pub name: String,
    pub pre_shared_key: Option<String>,
    pub auth: Option<AuthMode>,
    pub allowed_ips: Vec<String>,
}

impl ServerPeerConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.name.is_empty() || self.allowed_ips.is_empty() {
            return Err(ConfigError::Invalid(
                "each server peer needs a name and at least one allowed_ips prefix",
            ));
        }
        self.auth_mode_config()?;
        for prefix in &self.allowed_ips {
            prefix.parse::<IpNet>().map_err(|_| {
                ConfigError::Invalid("peer allowed_ips must contain valid CIDR prefixes")
            })?;
        }
        Ok(())
    }

    fn auth_mode_config(&self) -> Result<rvpn_crypto::AuthConfig, ConfigError> {
        if let Some(auth) = &self.auth {
            return auth.to_auth_config();
        }
        let psk = self.pre_shared_key.as_deref().ok_or(ConfigError::Invalid(
            "each server peer needs either `auth` or the legacy `pre_shared_key`",
        ))?;
        Ok(rvpn_crypto::AuthConfig::Psk(decode_psk(psk)?))
    }

    fn identity(&self) -> Result<PeerIdentity, ConfigError> {
        Ok(PeerIdentity {
            name: self.name.clone(),
            allowed_ips: self
                .allowed_ips
                .iter()
                .map(|prefix| prefix.parse())
                .collect::<Result<Vec<IpNet>, _>>()
                .map_err(|_| {
                    ConfigError::Invalid("peer allowed_ips must contain valid CIDR prefixes")
                })?,
            auth: self.auth_mode_config()?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CertificateAuthorityConfig {
    pub name: String,
    pub ca_public_key: String,
    pub local_identity_seed: String,
    pub local_certificate: String,
    #[serde(default)]
    pub default_allowed_ips: Vec<String>,
    #[serde(default)]
    pub peer_overrides: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub revoked_subjects: Vec<String>,
}

impl CertificateAuthorityConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        decode_psk(&self.ca_public_key)?;
        decode_psk(&self.local_identity_seed)?;
        decode_certificate(&self.local_certificate)?;
        for subject in &self.revoked_subjects {
            decode_psk(subject)?;
        }
        for prefixes in
            std::iter::once(&self.default_allowed_ips).chain(self.peer_overrides.values())
        {
            for prefix in prefixes {
                prefix.parse::<IpNet>().map_err(|_| {
                    ConfigError::Invalid(
                        "certificate_authority allowed_ips must contain valid CIDR prefixes",
                    )
                })?;
            }
        }
        Ok(())
    }

    pub fn to_auth_config(&self) -> Result<rvpn_crypto::AuthConfig, ConfigError> {
        Ok(rvpn_crypto::AuthConfig::Certificate {
            local_seed: decode_psk(&self.local_identity_seed)?,
            local_certificate: decode_certificate(&self.local_certificate)?,
            ca_public_key: decode_psk(&self.ca_public_key)?,
        })
    }

    pub fn resolve_allowed_ips(&self, subject_hex: &str) -> Result<Vec<IpNet>, ConfigError> {
        let prefixes = self
            .peer_overrides
            .get(subject_hex)
            .unwrap_or(&self.default_allowed_ips);
        prefixes
            .iter()
            .map(|p| p.parse())
            .collect::<Result<Vec<IpNet>, _>>()
            .map_err(|_| {
                ConfigError::Invalid(
                    "certificate_authority allowed_ips must contain valid CIDR prefixes",
                )
            })
    }

    pub fn is_revoked(&self, subject_hex: &str) -> bool {
        self.revoked_subjects
            .iter()
            .any(|s| s.eq_ignore_ascii_case(subject_hex))
    }
}

#[derive(Clone)]
pub struct PeerIdentity {
    pub name: String,
    pub allowed_ips: Vec<IpNet>,
    pub auth: rvpn_crypto::AuthConfig,
}

impl core::fmt::Debug for PeerIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PeerIdentity")
            .field("name", &self.name)
            .field("allowed_ips", &self.allowed_ips)
            .field("auth", &self.auth)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InterfaceConfig {
    pub name: Option<String>,
    pub tap_name: Option<String>,
    pub mtu: Option<u16>,
    pub mode: Option<DeviceMode>,
    pub address: Option<String>,
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
    pub fn mode(&self) -> DeviceMode {
        self.mode.unwrap_or_default()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
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

pub fn jittered_retry_interval(base_ms: u64, jitter_ms: u64) -> std::time::Duration {
    if jitter_ms == 0 {
        return std::time::Duration::from_millis(base_ms.max(1));
    }
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0) as u64;
    let span = 2 * jitter_ms + 1;
    let offset = (nanos % span) as i64 - jitter_ms as i64;
    let millis = (base_ms as i64 + offset).max(1) as u64;
    std::time::Duration::from_millis(millis)
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

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ClientRoutingConfig {
    #[serde(default)]
    pub default_route: bool,
    pub gateway: Option<String>,
    pub endpoint_gateway: Option<String>,
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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FirewallBackend {
    #[default]
    Auto,
    Iptables,
    Nftables,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
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

fn decode_certificate(value: &str) -> Result<[u8; 112], ConfigError> {
    if value.len() != 224 {
        return Err(ConfigError::InvalidCertificateEncoding);
    }
    let mut bytes = [0; 112];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| ConfigError::InvalidCertificateEncoding)?;
    Ok(bytes)
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid TOML configuration: {0}")]
    Parse(#[source] toml::de::Error),
    #[error("invalid configuration: {0}")]
    Invalid(&'static str),
    #[error(
        "pre_shared_key, identity seeds, and public keys must be exactly 32 bytes encoded as hexadecimal"
    )]
    InvalidPreSharedKey,
    #[error("certificate values must be exactly 112 bytes encoded as hexadecimal")]
    InvalidCertificateEncoding,
    #[error("failed to resolve server endpoint '{host}': {source}")]
    Resolution {
        host: String,
        #[source]
        source: std::io::Error,
    },
    #[error("server endpoint '{0}' did not resolve to any address")]
    NoResolvedAddress(String),
}

/// Base directory for RVPN's own config files: `$XDG_CONFIG_HOME/rvpn`,
/// falling back to `$HOME/.config/rvpn` on Linux/macOS, or
/// `%APPDATA%\rvpn` on Windows — so the same path resolves whether RVPN is
/// started by systemd (as that user) or run by hand.
pub fn default_config_dir() -> PathBuf {
    #[cfg(windows)]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            return PathBuf::from(appdata).join("rvpn");
        }
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        return PathBuf::from(xdg).join("rvpn");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".config").join("rvpn");
    }
    PathBuf::from("rvpn")
}

pub fn default_client_config_path() -> PathBuf {
    default_config_dir().join("client.toml")
}

pub fn default_server_config_path() -> PathBuf {
    default_config_dir().join("server.toml")
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
        assert!(matches!(
            config.auth_config().unwrap(),
            rvpn_crypto::AuthConfig::Psk(bytes) if bytes == [0xaa; 32]
        ));
        assert!(
            ClientConfig::from_toml("server = '127.0.0.1:9000'\npre_shared_key = 'bad'").is_err()
        );
    }

    #[test]
    fn accepts_hostname_shaped_server_syntax() {
        let config = ClientConfig::from_toml(
            "server = 'main-pc.lan:9000'\npre_shared_key = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'",
        ).unwrap();
        assert_eq!(config.server, "main-pc.lan:9000");
        assert!(ClientConfig::from_toml(
            "server = 'main-pc.lan'\npre_shared_key = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'"
        ).is_err());
    }

    #[tokio::test]
    async fn resolves_literal_ip_endpoint() {
        let resolved = resolve_endpoint("127.0.0.1:9000").await.unwrap();
        assert_eq!(resolved.port(), 9000);
        assert!(resolved.is_ipv4());
    }

    #[test]
    fn parses_provisioned_server_peers() {
        let config = ServerConfig::from_toml(
            "bind = '127.0.0.1:9000'\n[[peers]]\nname = 'laptop'\npre_shared_key = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\nallowed_ips = ['10.42.0.2/32']",
        ).unwrap();
        let peers = config.peer_identities().unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].name, "laptop");
    }

    #[test]
    fn parses_per_peer_pinned_key_auth() {
        let toml = r#"
bind = '0.0.0.0:9000'
[[peers]]
name = 'phone'
allowed_ips = ['10.42.0.3/32']
[peers.auth]
mode = 'pinned-key'
local_identity_seed = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
peer_public_key = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
"#;
        let config = ServerConfig::from_toml(toml).unwrap();
        let peers = config.peer_identities().unwrap();
        assert_eq!(peers.len(), 1);
        assert!(matches!(
            peers[0].auth,
            rvpn_crypto::AuthConfig::PinnedKey { .. }
        ));
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
