use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
};

use crate::util::{decode_certificate, decode_psk, validate_endpoint, validate_psk};
use crate::network::ConfigValidation;
use crate::ConfigError;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub bind: SocketAddr,
    pub pre_shared_key: Option<String>,
    #[serde(default)]
    pub peers: Vec<ServerPeerConfig>,
    #[serde(default)]
    pub links: Vec<LinkConfig>,
    pub certificate_authority: Option<CertificateAuthorityConfig>,
    #[serde(default)]
    pub interface: InterfaceConfig,
    #[serde(default)]
    pub handshake: HandshakeConfig,
    #[serde(default)]
    pub rekey: RekeyConfig,
    #[serde(default)]
    pub forwarding: ForwardingConfig,
    #[serde(default)]
    pub liveness: LivenessConfig,
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
        self.validate_links()?;
        self.interface
            .validate()
            .and_then(|_| self.handshake.validate())
            .and_then(|_| self.rekey.validate())
            .and_then(|_| self.forwarding.validate())
            .and_then(|_| self.liveness.validate())
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
    fn validate_links(&self) -> Result<(), ConfigError> {
        let mut names = std::collections::HashSet::new();
        for peer in &self.peers {
            if !names.insert(peer.name.as_str()) {
                return Err(ConfigError::DuplicatePeerName(peer.name.clone()));
            }
        }
        for link in &self.links {
            let mut members = std::collections::HashSet::new();
            for name in &link.between {
                let known = names.contains(name.as_str())
                    || (self.certificate_authority.is_some() && name.starts_with("cert:"));
                if !known {
                    return Err(ConfigError::UnknownLinkPeer(name.clone()));
                }
                members.insert(name.as_str());
            }
            if members.len() < 2 {
                return Err(ConfigError::Invalid(
                    "each [[links]] entry needs `between` to name at least two distinct peers",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

