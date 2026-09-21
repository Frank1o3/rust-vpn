use crate::{BestRoute, IpAddr, IpNet, KillSwitchSpec, NetConfigurator, NetError, RouteSpec};
use futures_util::stream::TryStreamExt;
use rtnetlink::{
    Handle, LinkMessageBuilder, LinkUnspec, RouteMessageBuilder,
    packet_route::route::{RouteAddress, RouteAttribute},
};
use std::net::{Ipv4Addr, Ipv6Addr};
use zbus::{Connection, Proxy};

use crate::linux_killswitch;

#[derive(Clone)]
pub struct SystemNet {
    handle: Handle,
}

impl SystemNet {
    pub fn new() -> Result<Self, NetError> {
        let (connection, handle, _) =
            rtnetlink::new_connection().map_err(|e| NetError::Operation(e.to_string()))?;
        tokio::spawn(connection);
        Ok(Self { handle })
    }

    async fn index(&self, name: &str) -> Result<u32, NetError> {
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(name.to_owned())
            .execute();
        links
            .try_next()
            .await
            .map_err(|e| NetError::Operation(e.to_string()))?
            .map(|link| link.header.index)
            .ok_or_else(|| NetError::InterfaceNotFound(name.to_owned()))
    }

    async fn resolve_proxy<'a>(
        &self,
        name: &str,
        connection: &'a Connection,
    ) -> Result<Proxy<'a>, NetError> {
        let index = self.index(name).await?;
        let path = format!("/org/freedesktop/resolve1/link/{index}");
        Proxy::new(
            connection,
            "org.freedesktop.resolve1",
            path,
            "org.freedesktop.resolve1.Link",
        )
        .await
        .map_err(|e| NetError::Operation(e.to_string()))
    }

    fn route_message(
        route: &RouteSpec,
    ) -> Result<rtnetlink::packet_route::route::RouteMessage, NetError> {
        match route.destination {
            IpNet::V4(net) => {
                let mut builder = RouteMessageBuilder::<Ipv4Addr>::new()
                    .destination_prefix(net.addr(), net.prefix_len());
                if let Some(gateway) = route.gateway {
                    let IpAddr::V4(gateway) = gateway else {
                        return Err(NetError::Operation(
                            "IPv4 route cannot use an IPv6 gateway".into(),
                        ));
                    };
                    builder = builder.gateway(gateway);
                }
                if let Some(source) = route.source {
                    let IpAddr::V4(source) = source else {
                        return Err(NetError::Operation(
                            "IPv4 route cannot use an IPv6 source".into(),
                        ));
                    };
                    builder = builder.pref_source(source);
                }
                if let Some(index) = route.interface_index {
                    builder = builder.output_interface(index);
                }
                Ok(builder.build())
            }
            IpNet::V6(net) => {
                let mut builder = RouteMessageBuilder::<Ipv6Addr>::new()
                    .destination_prefix(net.addr(), net.prefix_len());
                if let Some(gateway) = route.gateway {
                    let IpAddr::V6(gateway) = gateway else {
                        return Err(NetError::Operation(
                            "IPv6 route cannot use an IPv4 gateway".into(),
                        ));
                    };
                    builder = builder.gateway(gateway);
                }
                if let Some(source) = route.source {
                    let IpAddr::V6(source) = source else {
                        return Err(NetError::Operation(
                            "IPv6 route cannot use an IPv4 source".into(),
                        ));
                    };
                    builder = builder.pref_source(source);
                }
                if let Some(index) = route.interface_index {
                    builder = builder.output_interface(index);
                }
                Ok(builder.build())
            }
        }
    }
}

impl NetConfigurator for SystemNet {
    async fn interface_index(&self, name: &str) -> Result<u32, NetError> {
        self.index(name).await
    }

    async fn set_link_up(&self, name: &str) -> Result<(), NetError> {
        let index = self.index(name).await?;
        self.handle
            .link()
            .change(
                LinkMessageBuilder::<LinkUnspec>::new()
                    .index(index)
                    .up()
                    .build(),
            )
            .execute()
            .await
            .map_err(|e| NetError::Operation(e.to_string()))
    }

    async fn add_address(&self, name: &str, address: IpNet) -> Result<(), NetError> {
        let index = self.index(name).await?;
        self.handle
            .address()
            .add(index, address.addr(), address.prefix_len())
            .execute()
            .await
            .map_err(|e| NetError::Operation(e.to_string()))
    }

    async fn replace_route(&self, route: &RouteSpec) -> Result<(), NetError> {
        let message = Self::route_message(route)?;
        let _ = self.handle.route().del(message.clone()).execute().await;
        self.handle
            .route()
            .add(message)
            .execute()
            .await
            .map_err(|e| NetError::Operation(e.to_string()))
    }

    async fn delete_route(&self, route: &RouteSpec) -> Result<(), NetError> {
        let message = Self::route_message(route)?;
        self.handle
            .route()
            .del(message)
            .execute()
            .await
            .map_err(|e| NetError::Operation(e.to_string()))
    }

    async fn best_route_to(&self, destination: IpAddr) -> Result<BestRoute, NetError> {
        let message = match destination {
            IpAddr::V4(ip) => RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(ip, 32)
                .build(),
            IpAddr::V6(ip) => RouteMessageBuilder::<Ipv6Addr>::new()
                .destination_prefix(ip, 128)
                .build(),
        };
        let mut routes = self.handle.route().get(message).execute();
        let route = routes
            .try_next()
            .await
            .map_err(|e| NetError::Operation(e.to_string()))?
            .ok_or_else(|| NetError::Operation(format!("no route to {destination}")))?;

        let mut interface_index = None;
        let mut gateway = None;
        let mut source = None;
        for nla in route.attributes {
            match nla {
                RouteAttribute::Oif(index) => interface_index = Some(index),
                RouteAttribute::Gateway(address) => {
                    gateway = match address {
                        RouteAddress::Inet(value) => Some(IpAddr::V4(value)),
                        RouteAddress::Inet6(value) => Some(IpAddr::V6(value)),
                        _ => None,
                    };
                }
                RouteAttribute::PrefSource(address) | RouteAttribute::Source(address) => {
                    source = match address {
                        RouteAddress::Inet(value) => Some(IpAddr::V4(value)),
                        RouteAddress::Inet6(value) => Some(IpAddr::V6(value)),
                        _ => None,
                    };
                }
                _ => {}
            }
        }

        Ok(BestRoute {
            interface_index: interface_index
                .ok_or_else(|| NetError::Operation("route has no output interface".into()))?,
            gateway,
            source,
        })
    }

    async fn set_dns(&self, name: &str, servers: &[IpAddr]) -> Result<(), NetError> {
        let connection = Connection::system()
            .await
            .map_err(|e| NetError::Operation(e.to_string()))?;
        let proxy = self.resolve_proxy(name, &connection).await?;
        let addresses: Vec<(i32, Vec<u8>)> = servers
            .iter()
            .map(|address| match address {
                IpAddr::V4(value) => (2_i32, value.octets().to_vec()),
                IpAddr::V6(value) => (10_i32, value.octets().to_vec()),
            })
            .collect();
        proxy
            .call::<_, _, ()>("SetDNS", &addresses)
            .await
            .map_err(|e| NetError::Operation(e.to_string()))?;
        proxy
            .call::<_, _, ()>("SetDomains", &vec![("~.".to_owned(), true)])
            .await
            .map_err(|e| NetError::Operation(e.to_string()))?;
        proxy
            .call::<_, _, ()>("SetDefaultRoute", &true)
            .await
            .map_err(|e| NetError::Operation(e.to_string()))?;
        Ok(())
    }

    async fn revert_dns(&self, name: &str) -> Result<(), NetError> {
        let connection = Connection::system()
            .await
            .map_err(|e| NetError::Operation(e.to_string()))?;
        let proxy = self.resolve_proxy(name, &connection).await?;
        proxy
            .call::<_, _, ()>("Revert", &())
            .await
            .map_err(|e| NetError::Operation(e.to_string()))
    }

    async fn install_kill_switch(&self, spec: &KillSwitchSpec) -> Result<(), NetError> {
        let spec = spec.clone();
        tokio::task::spawn_blocking(move || linux_killswitch::install(&spec))
            .await
            .map_err(|e| NetError::Operation(e.to_string()))?
    }

    async fn remove_kill_switch(&self, uid: u32) -> Result<(), NetError> {
        tokio::task::spawn_blocking(move || linux_killswitch::remove(uid))
            .await
            .map_err(|e| NetError::Operation(e.to_string()))?
    }
}
