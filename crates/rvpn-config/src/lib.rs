//! TOML configuration parsing and validation for RVPN applications.

use ipnet::IpNet;
pub use rvpn_interface::DeviceMode;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr, path::PathBuf};
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

/// Authentication mode for one peer/CA relationship, shared by client and
/// server configuration. `mode` selects the variant in TOML, e.g.
/// `mode = "psk"`.
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "mode", rename_all = "kebab-case")]
pub enum AuthMode {
    /// Symmetric pre-shared key (32 bytes, hex-encoded).
    Psk { pre_shared_key: String },
    /// Both sides sign with a long-term Ed25519 key; each pins the other's
    /// public key directly (32-byte hex values).
    PinnedKey {
        local_identity_seed: String,
        peer_public_key: String,
    },
    /// Both sides sign with a long-term Ed25519 key; each side's key is
    /// authenticated via a certificate issued by a trusted CA rather than
    /// pinned directly. Generate values with
    /// `cargo run -p rvpn-crypto --example gen_ca_and_cert`.
    Certificate {
        local_identity_seed: String,
        /// Hex-encoded certificate proving `local_identity_seed`'s public key.
        local_certificate: String,
        /// Hex-encoded CA public key that issued `local_certificate`.
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

/// Client configuration for the initial authenticated UDP handshake.
#[derive(Clone, Deserialize, Serialize)]
pub struct ClientConfig {
    /// RVPN server endpoint as `host:port`, `ip:port`, or `[ipv6]:port`.
    /// Hostnames are resolved via DNS once at startup; see
    /// [`resolve_endpoint`]. A dynamic-DNS hostname whose IP changes after
    /// startup requires restarting the client to pick up the new address --
    /// this crate only resolves once, it does not watch for changes.
    pub server: String,
    /// Legacy flat pre-shared key. Ignored when `auth` is set; kept so
    /// existing configuration files keep working unchanged.
    pub pre_shared_key: Option<String>,
    /// Preferred way to configure authentication: PSK, pinned-key, or
    /// certificate. Falls back to `pre_shared_key` when omitted.
    pub auth: Option<AuthMode>,
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
    /// Optional 32-byte hex key. When set, every datagram is wrapped in a
    /// stream-cipher shell before hitting the wire so it carries no static
    /// magic bytes and no fixed length, defeating passive DPI fingerprinting.
    /// Both endpoints of a tunnel must share the same key.
    pub obfuscation_key: Option<String>,
}

impl ClientConfig {
    /// Parses and validates client TOML.
    pub fn from_toml(input: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(input).map_err(ConfigError::Parse)?;
        config.validate()?;
        Ok(config)
    }

    /// Syntactic validation only. `server` may be a hostname, so the
    /// endpoint's IP family (needed for `routing.endpoint_gateway*`) can
    /// only be checked once it has been resolved -- see [`Self::validate_resolved`].
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

    /// Family-dependent routing checks that require the resolved server
    /// address. Call this once after resolving `server` via DNS, before
    /// bringing up the tunnel.
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

    /// Resolves this client's authentication configuration: `auth` if set,
    /// otherwise the legacy flat `pre_shared_key` as PSK mode.
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

/// Resolves a `host:port`, `ip:port`, or `[ipv6]:port` endpoint via DNS.
///
/// Literal IP addresses resolve immediately without a real DNS query.
/// Picks the first resolved address; if a hostname resolves to both an IPv4
/// and an IPv6 record and the choice matters (for example, dual-stack
/// `routing.endpoint_gateway` selection), pin an explicit IP literal in
/// configuration instead of a hostname.
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

/// Checks that `value` has the syntactic shape `host:port` or `[ipv6]:port`
/// with a valid, non-zero port, without performing any DNS lookup.
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

/// Server configuration for the initial authenticated UDP handshake.
#[derive(Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    /// Static UDP address on which the server listens. Always a literal
    /// address -- a listening socket cannot bind to a resolved hostname.
    pub bind: SocketAddr,
    /// Legacy fallback PSK. Ignored once `peers` or `certificate_authority`
    /// is set; safe to delete once you have those configured.
    pub pre_shared_key: Option<String>,
    /// Statically provisioned client identities, each with its own auth mode.
    #[serde(default)]
    pub peers: Vec<ServerPeerConfig>,
    /// Optional CA trust anchor. Any client presenting a certificate signed
    /// by this CA is accepted without being individually enumerated in
    /// `peers`; see `peer_overrides`/`default_allowed_ips` for routing.
    pub certificate_authority: Option<CertificateAuthorityConfig>,
    /// Local TUN device settings used after session establishment.
    #[serde(default)]
    pub interface: InterfaceConfig,
    #[serde(default)]
    pub handshake: HandshakeConfig,
    #[serde(default)]
    pub rekey: RekeyConfig,
    #[serde(default)]
    pub forwarding: ForwardingConfig,
    /// Optional 32-byte hex key. When set, every datagram is wrapped in a
    /// stream-cipher shell before hitting the wire so it carries no static
    /// magic bytes and no fixed length, defeating passive DPI fingerprinting.
    /// Both endpoints of a tunnel must share the same key.
    pub obfuscation_key: Option<String>,
}

impl ServerConfig {
    /// Parses and validates server TOML.
    pub fn from_toml(input: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(input).map_err(ConfigError::Parse)?;
        config.validate()?;
        Ok(config)
    }

    /// Checks bind endpoint and authentication configuration.
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

    /// Returns provisioned peers with individually known identities (PSK or
    /// pinned-key), or the single legacy compatibility peer. Clients
    /// authenticated via `certificate_authority` are not enumerated here --
    /// their identity is only known once their certificate is verified
    /// during the handshake; see `apps/rvpn-server`'s handshake dispatch.
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

/// One statically provisioned RVPN client on a multi-client server.
#[derive(Clone, Deserialize, Serialize)]
pub struct ServerPeerConfig {
    pub name: String,
    /// Legacy flat pre-shared key. Ignored when `auth` is set.
    pub pre_shared_key: Option<String>,
    /// Preferred per-peer auth mode: PSK, pinned-key, or certificate.
    pub auth: Option<AuthMode>,
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

/// A CA trust anchor for certificate-based clients. One CA entry can cover
/// any number of actual devices without listing each one under `peers`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CertificateAuthorityConfig {
    pub name: String,
    /// Hex-encoded CA public key trusted to sign client certificates.
    pub ca_public_key: String,
    /// This server's own identity, presented to clients trusting this CA.
    pub local_identity_seed: String,
    pub local_certificate: String,
    /// Applied to any client whose certificate subject key isn't listed in
    /// `peer_overrides`. Empty means unrestricted -- recommended only for
    /// small trusted deployments; prefer explicit overrides otherwise.
    #[serde(default)]
    pub default_allowed_ips: Vec<String>,
    /// Per-client overrides keyed by the client's hex-encoded Ed25519
    /// subject public key (printed by `gen_ca_and_cert`).
    #[serde(default)]
    pub peer_overrides: HashMap<String, Vec<String>>,
    /// Hex-encoded Ed25519 subject public keys rejected even though their
    /// certificate hasn't expired yet — e.g. a lost or compromised device.
    /// Checked only *after* the certificate's signature already verified,
    /// so it never gives an unauthenticated probe information.
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

    /// Resolves the allowed_ips for a client whose certificate subject key
    /// (hex-encoded) is `subject_hex`.
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

/// Validated server-side identity used by the application session table.
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
    /// +/- jitter (ms) applied around `retry_interval_ms` on every
    /// retransmission, so retries don't repeat at a fixed, fingerprint-able
    /// cadence. Zero disables jitter.
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

/// Returns `base_ms` perturbed by up to +/- `jitter_ms`, floored at 1ms.
/// This only needs to defeat passive averaging of a fixed cadence, not
/// resist an adversary who can see our clock, so a non-cryptographic
/// jitter source is fine here.
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

fn decode_certificate(value: &str) -> Result<[u8; 112], ConfigError> {
    if value.len() != 224 {
        return Err(ConfigError::InvalidCertificateEncoding);
    }
    let mut bytes = [0; 112];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| ConfigError::InvalidCertificateEncoding)?;
    Ok(bytes)
}

/// Configuration parsing and validation errors.
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
