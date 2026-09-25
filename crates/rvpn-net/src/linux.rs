use crate::{BestRoute, IpAddr, IpNet, KillSwitchSpec, NetConfigurator, NetError, RouteSpec};
use futures_util::stream::TryStreamExt;
use rtnetlink::{
    Handle, LinkMessageBuilder, LinkUnspec, RouteMessageBuilder,
    packet_route::route::{RouteAddress, RouteAttribute},
};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::sync::OnceCell;
use zbus::{
    Connection, Proxy,
    zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value},
};

use crate::linux_killswitch;

const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";
const RESOLV_CONF_BACKUP_PATH: &str = "/etc/resolv.conf.rvpn-backup";
const NETWORKMANAGER_CONF_PATH: &str = "/etc/NetworkManager/NetworkManager.conf";

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
            .cloned()
    }

    async fn resolved_service_available(connection: &Connection) -> Result<bool, NetError> {
        let dbus = Proxy::new(
            connection,
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
        )
        .await
        .map_err(|e| NetError::Operation(e.to_string()))?;
        let names: Vec<String> = dbus
            .call("ListActivatableNames", &())
            .await
            .map_err(|e| NetError::Operation(e.to_string()))?;
        Ok(names.iter().any(|n| n == "org.freedesktop.resolve1"))
    }

    async fn network_manager_manages_dns() -> bool {
        let Ok(contents) = tokio::fs::read_to_string(NETWORKMANAGER_CONF_PATH).await else {
            return false;
        };

        let mut in_main_section = false;
        for raw_line in contents.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                in_main_section = line.eq_ignore_ascii_case("[main]");
                continue;
            }
            if !in_main_section {
                continue;
            }
            if let Some((key, value)) = line.split_once('=')
                && key.trim().eq_ignore_ascii_case("dns")
                && value.trim().eq_ignore_ascii_case("default")
            {
                return true;
            }
        }
        false
    }

    async fn set_dns_resolv_conf_fallback(servers: &[IpAddr]) -> Result<(), NetError> {
        if tokio::fs::metadata(RESOLV_CONF_BACKUP_PATH).await.is_err()
            && let Ok(current) = tokio::fs::read(RESOLV_CONF_PATH).await
        {
            tokio::fs::write(RESOLV_CONF_BACKUP_PATH, current)
                .await
                .map_err(|e| NetError::Operation(format!("backing up resolv.conf: {e}")))?;
        }

        let mut contents = String::from("# Managed by RVPN (systemd-resolved unavailable)\n");
        for server in servers {
            contents.push_str(&format!("nameserver {server}\n"));
        }

        tokio::fs::write(RESOLV_CONF_PATH, contents)
            .await
            .map_err(|e| NetError::Operation(format!("writing resolv.conf: {e}")))
    }

    async fn revert_dns_resolv_conf_fallback() -> Result<(), NetError> {
        if let Ok(backup) = tokio::fs::read(RESOLV_CONF_BACKUP_PATH).await {
            tokio::fs::write(RESOLV_CONF_PATH, backup)
                .await
                .map_err(|e| NetError::Operation(format!("restoring resolv.conf: {e}")))?;
            let _ = tokio::fs::remove_file(RESOLV_CONF_BACKUP_PATH).await;
        }
        Ok(())
    }

    async fn network_manager_dns_mode(connection: &Connection) -> Result<String, NetError> {
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

    async fn set_dns_networkmanager(
        &self,
        name: &str,
        servers: &[IpAddr],
        connection: &Connection,
    ) -> Result<(), NetError> {
        if let Err(e) = Self::revert_dns_networkmanager(connection, name).await {
            tracing::debug!(
                interface = name,
                %e,
                "no stale NetworkManager RVPN DNS profile to clean up before (re)configuring"
            );
        }

        let manager = Proxy::new(
            connection,
            "org.freedesktop.NetworkManager",
            "/org/freedesktop/NetworkManager",
            "org.freedesktop.NetworkManager",
        )
        .await
        .map_err(|e| NetError::Operation(e.to_string()))?;

        let device_path: OwnedObjectPath = manager
            .call("GetDeviceByIpIface", &name)
            .await
            .map_err(|e| {
                NetError::Operation(format!(
                    "NetworkManager does not know about interface {name} yet: {e}"
                ))
            })?;

        let v4_dns: Vec<u32> = servers
            .iter()
            .filter_map(|addr| match addr {
                IpAddr::V4(v4) => Some(u32::from_be_bytes(v4.octets())),
                IpAddr::V6(_) => None,
            })
            .collect();
        let v6_dns: Vec<Vec<u8>> = servers
            .iter()
            .filter_map(|addr| match addr {
                IpAddr::V6(v6) => Some(v6.octets().to_vec()),
                IpAddr::V4(_) => None,
            })
            .collect();

        if v4_dns.is_empty() && v6_dns.is_empty() {
            return Err(NetError::Operation(
                "no DNS servers to configure via NetworkManager".into(),
            ));
        }

        let mut connection_settings: HashMap<&str, Value<'static>> = HashMap::new();
        connection_settings.insert("id", Value::from(format!("RVPN DNS {name}")));
        connection_settings.insert("type", Value::from("generic"));
        connection_settings.insert("interface-name", Value::from(name.to_owned()));
        connection_settings.insert("autoconnect", Value::from(false));

        let mut settings: HashMap<&str, HashMap<&str, Value<'static>>> = HashMap::new();
        settings.insert("connection", connection_settings);

        if !v4_dns.is_empty() {
            let mut ipv4_settings: HashMap<&str, Value<'static>> = HashMap::new();
            ipv4_settings.insert("method", Value::from("link-local"));
            ipv4_settings.insert("dns", Value::from(v4_dns));
            ipv4_settings.insert("dns-priority", Value::from(-1_i32));
            ipv4_settings.insert("ignore-auto-dns", Value::from(true));
            settings.insert("ipv4", ipv4_settings);
        }

        if !v6_dns.is_empty() {
            let mut ipv6_settings: HashMap<&str, Value<'static>> = HashMap::new();
            ipv6_settings.insert("method", Value::from("link-local"));
            ipv6_settings.insert("dns", Value::from(v6_dns));
            ipv6_settings.insert("dns-priority", Value::from(-1_i32));
            ipv6_settings.insert("ignore-auto-dns", Value::from(true));
            settings.insert("ipv6", ipv6_settings);
        }

        let specific_object = ObjectPath::try_from("/")
            .map_err(|e| NetError::Operation(format!("invalid NetworkManager object path: {e}")))?;
        let options: HashMap<&str, Value<'static>> = HashMap::new();

        manager
            .call::<_, _, (OwnedObjectPath, OwnedObjectPath, HashMap<String, OwnedValue>)>(
                "AddAndActivateConnection2",
                &(settings, device_path, specific_object, options),
            )
            .await
            .map_err(|e| {
                NetError::Operation(format!(
                    "NetworkManager AddAndActivateConnection2 failed for RVPN DNS profile on {name}: {e}"
                ))
            })?;

        tracing::info!(
            interface = name,
            dns = ?servers,
            "configured DNS via NetworkManager (NetworkManager.conf sets dns=default)"
        );
        Ok(())
    }

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

    async fn revert_dns_resolved(
        &self,
        name: &str,
        connection: &Connection,
    ) -> Result<(), NetError> {
        let proxy = self.resolve_proxy(name, connection).await?;
        proxy.call::<_, _, ()>("Revert", &()).await.map_err(|e| {
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

        if Self::network_manager_manages_dns().await {
            tracing::info!(
                interface = name,
                "NetworkManager.conf sets `dns=default` under [main]; \
                 configuring RVPN DNS via NetworkManager instead of systemd-resolved"
            );
            return self
                .set_dns_networkmanager(name, servers, &connection)
                .await;
        }

        if !Self::resolved_service_available(&connection)
            .await
            .unwrap_or(false)
        {
            tracing::warn!(
                interface = name,
                "org.freedesktop.resolve1 is not installed/activatable on this host; \
                 falling back to writing /etc/resolv.conf directly (best-effort — may be \
                 overwritten later by NetworkManager or another DNS manager)"
            );
            return Self::set_dns_resolv_conf_fallback(servers).await;
        }

        match Self::network_manager_dns_mode(&connection).await {
            Ok(mode) => {
                tracing::info!(
                    interface = name,
                    nm_dns_mode = %mode,
                    "configuring RVPN DNS via systemd-resolved per-link API"
                );
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

        if Self::network_manager_manages_dns().await {
            return Self::revert_dns_networkmanager(&connection, name).await;
        }

        if !Self::resolved_service_available(&connection)
            .await
            .unwrap_or(false)
        {
            return Self::revert_dns_resolv_conf_fallback().await;
        }

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
