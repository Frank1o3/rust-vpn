mod basic;
mod error;
mod network;
mod server;
mod util;

#[cfg(test)]
mod tests;

pub use basic::{AuthMode, ClientConfig, Config, LinkConfig};
pub use error::ConfigError;
pub use network::{
    ClientRoutingConfig, DeviceMode, FirewallBackend, ForwardingConfig, HandshakeConfig,
    InterfaceConfig, LivenessConfig, RekeyConfig,
};
pub use server::{CertificateAuthorityConfig, PeerIdentity, ServerConfig, ServerPeerConfig};
pub use util::{
    default_client_config_path, default_config_dir, default_server_config_path,
    jittered_retry_interval, read_config_file, resolve_endpoint, validate_endpoint_syntax,
};
