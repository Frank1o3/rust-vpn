use crate::{BestRoute, IpAddr, IpNet, KillSwitchSpec, NetConfigurator, NetError, RouteSpec};
use futures_util::stream::TryStreamExt;
use rtnetlink::{
    Handle, LinkMessageBuilder, LinkUnspec, RouteMessageBuilder,
    packet_route::route::{RouteAddress, RouteAttribute},
};
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::sync::OnceCell;
use zbus::{
    zvariant::OwnedObjectPath,
    Connection, Proxy,
};

use crate::linux_killswitch;

#[derive(Clone)]
pub struct SystemNet {
    handle: Handle,
}

static SYSTEM_BUS: OnceCell<Connection> = OnceCell::const_new();

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

    async fn system_bus() -> Result<Connection, NetError> {
        SYSTEM_BUS
            .get_or_try_init(|| async {
                Connection::system()
                    .await
                    .map_err(|e| NetError::Operation(e.to_string()))
            })
            .await
            .map(Clone::clone)
    }

    /// Query NetworkManager for its current DNS processing mode.
    ///
    /// Common return values: `"default"`, `"dnsmasq"`, `"systemd-resolved"`,
    /// `"none"`.  Returns an error when NetworkManager is not running or the
    /// DnsManager interface is unavailable.
    async fn network_manager_dns_mode(
        connection: &Connection,
    ) -> Result<String, NetError> {
        let proxy = Proxy::new(
            connection,
            "org.freedesktop.NetworkManager",
            "/org/freedesktop/NetworkManager/DnsManager",
            "org.freedesktop.NetworkManager.DnsManager",
        )
        .await
        .map_err(|e| NetError::Operation(e.to_string()))?;
        proxy
            .get_property::<String>("Mode")
            .await
            .map_err(|e| NetError::Operation(e.to_string()))
    }

    /// Deactivate any RVPN DNS connection profile that NetworkManager is
    /// currently holding for `name`.
    ///
    /// This cleans up volatile `"RVPN DNS {name}"` profiles that may have been
    /// left behind by a previous RVPN version which used
    /// `AddAndActivateConnection2`, or by a reconnect cycle.  It is safe to
    /// call unconditionally — if no such profile exists the function returns
    /// `Ok(())`.
    async fn revert_dns_networkmanager(
        connection: &Connection,
        name: &str,
    ) -> Result<(), NetError> {
        let manager = Proxy::new(
            connection,
            "org.freedesktop.NetworkManager",
            "/org/freedesktop/NetworkManager",
            "org.freedesktop.NetworkManager",
        )
        .await
        .map_err(|e| NetError::Operation(e.to_string()))?;

        let device: OwnedObjectPath = match manager
            .call::<_, _, OwnedObjectPath>("GetDeviceByIpIface", &name)
            .await
        {
            Ok(device) => device,
            Err(_) => return Ok(()),
        };

        let device_proxy = Proxy::new(
            connection,
            "org.freedesktop.NetworkManager",
            device.as_str(),
            "org.freedesktop.NetworkManager.Device",
        )
        .await
        .map_err(|e| NetError::Operation(e.to_string()))?;

        let active: OwnedObjectPath = device_proxy
            .get_property("ActiveConnection")
            .await
            .map_err(|e| NetError::Operation(e.to_string()))?;
        if active.as_str() == "/" {
            return Ok(());
        }

        let active_proxy = Proxy::new(
            connection,
            "org.freedesktop.NetworkManager",
            active.as_str(),
            "org.freedesktop.NetworkManager.Connection.Active",
        )
        .await
        .map_err(|e| NetError::Operation(e.to_string()))?;
        let id = active_proxy
            .get_property::<String>("Id")
            .await
            .map_err(|e| NetError::Operation(e.to_string()))?;

        if id != format!("RVPN DNS {name}") {
            return Ok(());
        }

        manager
            .call::<_, _, ()>("DeactivateConnection", &active)
            .await
            .map_err(|e| NetError::Operation(e.to_string()))?;

        Ok(())
    }

    /// Build a `org.freedesktop.resolve1.Link` proxy for the given interface.
    ///
    /// The proxy targets `/org/freedesktop/resolve1/link/{index}` where
    /// `index` is the kernel interface index obtained via rtnetlink.
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

    /// Configure per-link DNS on `name` through `org.freedesktop.resolve1`.
    ///
    /// Sets the DNS server list, makes `"~."` a routing domain so that all
    /// queries are eligible to be routed through this link, and marks the link
    /// as the default DNS route.
    async fn set_dns_resolved(
        &self,
        name: &str,
        servers: &[IpAddr],
        connection: &Connection,
    ) -> Result<(), NetError> {
        let proxy = self.resolve_proxy(name, connection).await?;
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
            .map_err(|e| {
                NetError::Operation(format!(
                    "systemd-resolved SetDNS failed for interface {name}: {e}"
                ))
            })?;
        proxy
            .call::<_, _, ()>("SetDomains", &vec![("~.".to_owned(), true)])
            .await
            .map_err(|e| {
                NetError::Operation(format!(
                    "systemd-resolved SetDomains failed for interface {name}: {e}"
                ))
            })?;
        proxy
            .call::<_, _, ()>("SetDefaultRoute", &true)
            .await
            .map_err(|e| {
                NetError::Operation(format!(
                    "systemd-resolved SetDefaultRoute failed for interface {name}: {e}"
                ))
            })?;
        Ok(())
    }

    /// Revert per-link DNS on `name` through `org.freedesktop.resolve1`.
    async fn revert_dns_resolved(
        &self,
        name: &str,
        connection: &Connection,
    ) -> Result<(), NetError> {
        let proxy = self.resolve_proxy(name, connection).await?;
        proxy
            .call::<_, _, ()>("Revert", &())
            .await
            .map_err(|e| {
                NetError::Operation(format!(
                    "systemd-resolved Revert failed for interface {name}: {e}"
                ))
            })
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
        let connection = Self::system_bus().await?;

        // NetworkManager's AddAndActivateConnection2 API cannot handle
        // TUN/TAP interfaces created externally (outside NM) — it fails with
        // "failed to determine interface name for a TUN" regardless of the
        // connection type ("tun", "generic", etc.) because NM internally
        // classifies the device as NMDeviceTun and cannot activate against it.
        //
        // Instead, we always configure per-link DNS through systemd-resolved's
        // org.freedesktop.resolve1.Link D-Bus interface.  This is the standard
        // per-link DNS API on systemd-based Linux systems and works correctly
        // regardless of NetworkManager's dns= mode:
        //
        //   dns=systemd-resolved  →  NM pushes its own DNS to resolved; our
        //                            per-link config coexists with priority set
        //                            by the routing domain ("~.").
        //   dns=default           →  On systems with resolved, /etc/resolv.conf
        //                            points to the resolved stub (127.0.0.53),
        //                            so per-link resolved config is effective.
        //   dns=dnsmasq           →  Similar — resolved handles per-link routing.
        //   dns=none              →  NM does not touch DNS; resolved is the
        //                            sole manager.
        //
        // Detect the NM DNS mode for diagnostics/logging.
        match Self::network_manager_dns_mode(&connection).await {
            Ok(mode) => {
                tracing::info!(
                    interface = name,
                    nm_dns_mode = %mode,
                    "configuring RVPN DNS via systemd-resolved per-link API"
                );
                // Clean up any stale NM DNS profile from a previous RVPN
                // version that used AddAndActivateConnection2.
                if let Err(e) = Self::revert_dns_networkmanager(&connection, name).await {
                    tracing::debug!(
                        interface = name,
                        %e,
                        "no stale NetworkManager RVPN DNS profile to clean up"
                    );
                }
            }
            Err(error) => {
                tracing::debug!(
                    %error,
                    "NetworkManager D-Bus unavailable; configuring DNS via systemd-resolved"
                );
            }
        }

        self.set_dns_resolved(name, servers, &connection).await
    }

    async fn revert_dns(&self, name: &str) -> Result<(), NetError> {
        let connection = Self::system_bus().await?;

        // Clean up any stale NetworkManager RVPN DNS profile (from a previous
        // version that used AddAndActivateConnection2).  Safe to call even
        // when no such profile exists.
        if let Err(e) = Self::revert_dns_networkmanager(&connection, name).await {
            tracing::debug!(
                interface = name,
                %e,
                "no NetworkManager RVPN DNS profile to deactivate"
            );
        }

        self.revert_dns_resolved(name, &connection).await
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
