use crate::{BestRoute, IpAddr, IpNet, KillSwitchSpec, NetConfigurator, NetError, RouteSpec};

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemNet;

impl NetConfigurator for SystemNet {
    async fn interface_index(&self, _: &str) -> Result<u32, NetError> { Err(NetError::Unsupported) }
    async fn set_link_up(&self, _: &str) -> Result<(), NetError> { Err(NetError::Unsupported) }
    async fn add_address(&self, _: &str, _: IpNet) -> Result<(), NetError> { Err(NetError::Unsupported) }
    async fn replace_route(&self, _: &RouteSpec) -> Result<(), NetError> { Err(NetError::Unsupported) }
    async fn delete_route(&self, _: &RouteSpec) -> Result<(), NetError> { Err(NetError::Unsupported) }
    async fn best_route_to(&self, _: IpAddr) -> Result<BestRoute, NetError> { Err(NetError::Unsupported) }
    async fn set_dns(&self, _: &str, _: &[IpAddr]) -> Result<(), NetError> { Err(NetError::Unsupported) }
    async fn revert_dns(&self, _: &str) -> Result<(), NetError> { Err(NetError::Unsupported) }
    async fn install_kill_switch(&self, _: &KillSwitchSpec) -> Result<(), NetError> { Err(NetError::Unsupported) }
    async fn remove_kill_switch(&self, _: u32) -> Result<(), NetError> { Err(NetError::Unsupported) }
}
