use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};
use thiserror::Error;

mod unsupported;
#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::SystemNet;
#[cfg(not(target_os = "linux"))]
pub use unsupported::SystemNet;

#[derive(Debug, Error)]
pub enum NetError {
    #[error("network operation failed: {0}")]
    Operation(String),
    #[error("interface '{0}' was not found")]
    InterfaceNotFound(String),
    #[error("unsupported native networking operation on this platform")]
    Unsupported,
    #[error("invalid network prefix: {0}")]
    InvalidPrefix(String),
}

impl From<std::io::Error> for NetError {
    fn from(value: std::io::Error) -> Self {
        Self::Operation(value.to_string())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BestRoute {
    pub interface_index: u32,
    pub gateway: Option<IpAddr>,
    pub source: Option<IpAddr>,
}

#[derive(Clone, Debug)]
pub struct RouteSpec {
    pub destination: IpNet,
    pub gateway: Option<IpAddr>,
    pub interface_index: Option<u32>,
    pub source: Option<IpAddr>,
}

#[derive(Clone, Debug)]
pub struct KillSwitchSpec {
    pub endpoint: SocketAddr,
    pub tunnel_interface: String,
    pub uid: u32,
}

pub trait NetConfigurator: Send + Sync {
    async fn interface_index(&self, name: &str) -> Result<u32, NetError>;
    async fn set_link_up(&self, name: &str) -> Result<(), NetError>;
    async fn add_address(&self, name: &str, address: IpNet) -> Result<(), NetError>;
    async fn replace_route(&self, route: &RouteSpec) -> Result<(), NetError>;
    async fn delete_route(&self, route: &RouteSpec) -> Result<(), NetError>;
    async fn best_route_to(&self, destination: IpAddr) -> Result<BestRoute, NetError>;
    async fn set_dns(&self, name: &str, servers: &[IpAddr]) -> Result<(), NetError>;
    async fn revert_dns(&self, name: &str) -> Result<(), NetError>;
    async fn install_kill_switch(&self, spec: &KillSwitchSpec) -> Result<(), NetError>;
    async fn remove_kill_switch(&self, uid: u32) -> Result<(), NetError>;
}

pub fn cidr(value: &str) -> Result<IpNet, NetError> {
    value
        .parse()
        .map_err(|_| NetError::InvalidPrefix(value.to_owned()))
}
