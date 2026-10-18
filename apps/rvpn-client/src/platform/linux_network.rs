use anyhow::{Context, Result};
use ipnet::IpNet;
use rvpn_config::ClientConfig;
use rvpn_interface::{DeviceMode, TunConfig, VirtualInterface};
use rvpn_net::{KillSwitchSpec, NetConfigurator, RouteSpec, SystemNet};
use std::net::{IpAddr, SocketAddr};

pub async fn create_client_devices(
    config: &ClientConfig,
    mode: DeviceMode,
    mtu: u16,
) -> Result<(Option<VirtualInterface>, Option<VirtualInterface>, bool)> {
    let tun_name = client_interface_name(config.interface.name.as_deref(), false);
    let tap_name = config.interface.tap_name.clone().or_else(|| {
        if mode == DeviceMode::Tap {
            Some(tun_name.clone())
        } else {
            Some(client_interface_name(Some(&tun_name), true))
        }
    });
    let networkmanager = SystemNet::new().context("opening Linux networking backend")?;

    if networkmanager.networkmanager_client_tun_available().await {
        match create_networkmanager_client_devices(
            &networkmanager,
            config,
            mode,
            mtu,
            &tun_name,
            tap_name.as_deref(),
        )
        .await
        {
            Ok((tun, tap)) => return Ok((tun, tap, true)),
            Err(error) => tracing::warn!(
                %error,
                "NetworkManager could not create RVPN client devices; using native TUN/TAP creation"
            ),
        }
    }

    let (tun, tap) =
        create_native_client_devices(mode, mtu, &tun_name, tap_name.as_deref()).await?;
    Ok((tun, tap, false))
}

async fn create_networkmanager_client_devices(
    net: &SystemNet,
    config: &ClientConfig,
    mode: DeviceMode,
    mtu: u16,
    tun_name: &str,
    tap_name: Option<&str>,
) -> Result<(Option<VirtualInterface>, Option<VirtualInterface>)> {
    let addresses = config
        .interface
        .address
        .iter()
        .chain(&config.interface.addresses)
        .map(|address| {
            address
                .parse::<IpNet>()
                .with_context(|| format!("invalid configured interface address: {address}"))
        })
        .collect::<Result<Vec<_>>>()?;
    let dns_servers = config.interface.dns_server_list()?;
    let owner_uid = unsafe { libc::geteuid() };
    let group_gid = unsafe { libc::getegid() };
    let (tun_mode, tap_mode) = match mode {
        DeviceMode::Tun => (true, false),
        DeviceMode::Tap => (false, true),
        DeviceMode::Both => (true, true),
    };

    let tun = if tun_mode {
        let (addresses, dns_servers) = if mode == DeviceMode::Tap {
            (&[][..], &[][..])
        } else {
            (addresses.as_slice(), dns_servers.as_slice())
        };
        Some(
            create_networkmanager_device(
                net,
                tun_name,
                mtu,
                DeviceMode::Tun,
                owner_uid,
                group_gid,
                addresses,
                dns_servers,
            )
            .await?,
        )
    } else {
        None
    };

    let tap = if tap_mode {
        let is_primary = mode == DeviceMode::Tap;
        match create_networkmanager_device(
            net,
            tap_name.context("missing configured TAP interface name")?,
            mtu,
            DeviceMode::Tap,
            owner_uid,
            group_gid,
            if is_primary { &addresses } else { &[] },
            if is_primary { &dns_servers } else { &[] },
        )
        .await
        {
            Ok(tap) => Some(tap),
            Err(error) => {
                if let Some(tun) = &tun {
                    let _ = net.deactivate_networkmanager_client_tun(tun.name()).await;
                }
                return Err(error);
            }
        }
    } else {
        None
    };

    Ok((tun, tap))
}

async fn create_networkmanager_device(
    net: &SystemNet,
    name: &str,
    mtu: u16,
    mode: DeviceMode,
    owner_uid: u32,
    group_gid: u32,
    addresses: &[IpNet],
    dns_servers: &[IpAddr],
) -> Result<VirtualInterface> {
    let mode_number = match mode {
        DeviceMode::Tun => 1,
        DeviceMode::Tap => 2,
        DeviceMode::Both => anyhow::bail!("NetworkManager cannot create a combined TUN/TAP device"),
    };
    let tun_config = TunConfig {
        name: Some(name.to_owned()),
        mtu,
        mode,
    };
    tun_config.validate()?;
    net.create_networkmanager_client_tun(
        name,
        mtu,
        mode_number,
        owner_uid,
        group_gid,
        addresses,
        dns_servers,
    )
    .await?;
    match VirtualInterface::attach(tun_config).await {
        Ok(device) => Ok(device),
        Err(error) => {
            let _ = net.deactivate_networkmanager_client_tun(name).await;
            Err(error.into())
        }
    }
}

async fn create_native_client_devices(
    mode: DeviceMode,
    mtu: u16,
    tun_name: &str,
    tap_name: Option<&str>,
) -> Result<(Option<VirtualInterface>, Option<VirtualInterface>)> {
    let tun = if matches!(mode, DeviceMode::Tun | DeviceMode::Both) {
        Some(
            VirtualInterface::create(TunConfig {
                name: Some(tun_name.to_owned()),
                mtu,
                mode: DeviceMode::Tun,
            })
            .await?,
        )
    } else {
        None
    };
    let tap = if matches!(mode, DeviceMode::Tap | DeviceMode::Both) {
        match VirtualInterface::create(TunConfig {
            name: Some(
                tap_name
                    .context("missing configured TAP interface name")?
                    .to_owned(),
            ),
            mtu,
            mode: DeviceMode::Tap,
        })
        .await
        {
            Ok(tap) => Some(tap),
            Err(error) => {
                drop(tun);
                return Err(error.into());
            }
        }
    } else {
        None
    };
    Ok((tun, tap))
}

fn client_interface_name(configured: Option<&str>, tap: bool) -> String {
    if let Some(name) = configured {
        if tap {
            return format!("{}-tap", name.chars().take(11).collect::<String>());
        }
        return name.to_owned();
    }
    let process_id = std::process::id() % 1_000_000_000;
    if tap {
        format!("rvpt{process_id}")
    } else {
        format!("rvpn{process_id}")
    }
}

pub async fn install_bootstrap_kill_switch(config: &ClientConfig) -> Result<bool> {
    if !config.routing.default_route && !config.routing.default_route_v6 {
        return Ok(false);
    }
    let endpoint = config
        .server
        .parse::<SocketAddr>()
        .context("default-route bootstrap requires a numeric VPN endpoint")?;
    let uid = unsafe { libc::geteuid() };
    let net = SystemNet::new().context("opening Linux networking backend")?;
    net.install_kill_switch(&KillSwitchSpec {
        endpoint,
        tunnel_interface: None,
        uid,
    })
    .await
    .context("installing Linux bootstrap kill switch")?;
    tracing::info!(uid, %endpoint, "Linux bootstrap kill switch is active before endpoint resolution");
    Ok(true)
}

pub async fn remove_bootstrap_kill_switch() -> Result<()> {
    let uid = unsafe { libc::geteuid() };
    SystemNet::new()
        .context("opening Linux networking backend")?
        .remove_kill_switch(uid)
        .await
        .context("removing Linux bootstrap kill switch")
}

pub async fn configure_client_network(
    dev: &VirtualInterface,
    config: &ClientConfig,
    server: SocketAddr,
    networkmanager_managed: bool,
) -> Result<()> {
    let net = SystemNet::new().context("opening Linux rtnetlink connection")?;
    let interface_index = net.interface_index(dev.name()).await?;

    if config.routing.default_route || config.routing.default_route_v6 {
        let uid = unsafe { libc::geteuid() };
        net.install_kill_switch(&KillSwitchSpec {
            endpoint: server,
            tunnel_interface: Some(dev.name().to_owned()),
            uid,
        })
        .await
        .context("updating Linux kill switch for tunnel interface")?;
    }

    net.set_link_up(dev.name()).await?;

    if !networkmanager_managed {
        for address in config
            .interface
            .address
            .iter()
            .chain(&config.interface.addresses)
        {
            let prefix: IpNet = address
                .parse()
                .with_context(|| format!("invalid configured interface address: {address}"))?;
            net.add_address(dev.name(), prefix).await?;
        }
    }

    for route in &config.routing.routes {
        let destination = route
            .parse::<IpNet>()
            .with_context(|| format!("invalid configured route: {route}"))?;
        net.replace_route(&RouteSpec {
            destination,
            gateway: None,
            interface_index: Some(interface_index),
            source: None,
        })
        .await
        .with_context(|| {
            format!(
                "installing configured route {destination} on interface {} ({interface_index})",
                dev.name()
            )
        })?;
    }

    if config.routing.default_route {
        let gateway: IpAddr = config
            .routing
            .gateway
            .as_deref()
            .expect("validated gateway")
            .parse()
            .context("parsing IPv4 tunnel gateway")?;
        if !gateway.is_ipv4() {
            anyhow::bail!("IPv4 default routing requires an IPv4 tunnel gateway");
        }

        preserve_server_route(&net, server).await?;
        let source = tunnel_source(config, false)?;
        let destination_1: IpNet = "0.0.0.0/1".parse().unwrap();
        let destination_2: IpNet = "128.0.0.0/1".parse().unwrap();
        for destination in [destination_1, destination_2] {
            net.replace_route(&RouteSpec {
                destination,
                gateway: Some(gateway),
                interface_index: Some(interface_index),
                source: Some(source),
            })
            .await
            .with_context(|| {
                format!(
                    "installing IPv4 tunnel route {destination} via {gateway} on interface {} ({interface_index})",
                    dev.name()
                )
            })?;
        }
    }

    if config.routing.default_route_v6 {
        let gateway: IpAddr = config
            .routing
            .gateway_v6
            .as_deref()
            .expect("validated gateway_v6")
            .parse()
            .context("parsing IPv6 tunnel gateway")?;
        if !gateway.is_ipv6() {
            anyhow::bail!("IPv6 default routing requires an IPv6 tunnel gateway");
        }

        preserve_server_route(&net, server).await?;
        let source = tunnel_source(config, true)?;
        let destination_1: IpNet = "::/1".parse().unwrap();
        let destination_2: IpNet = "8000::/1".parse().unwrap();
        for destination in [destination_1, destination_2] {
            net.replace_route(&RouteSpec {
                destination,
                gateway: Some(gateway),
                interface_index: Some(interface_index),
                source: Some(source),
            })
            .await
            .with_context(|| {
                format!(
                    "installing IPv6 tunnel route {destination} via {gateway} on interface {} ({interface_index})",
                    dev.name()
                )
            })?;
        }
    }

    if !networkmanager_managed
        && let Ok(dns_servers) = config.interface.dns_server_list()
        && !dns_servers.is_empty()
    {
        if let Err(error) = net.set_dns(dev.name(), &dns_servers).await {
            tracing::warn!(
                %error,
                "native Linux DNS backend rejected RVPN DNS configuration"
            );
        } else {
            tracing::info!(
                interface = dev.name(),
                dns = ?dns_servers,
                "configured DNS servers for RVPN interface"
            );
        }
    }

    Ok(())
}

async fn preserve_server_route(net: &SystemNet, server: SocketAddr) -> Result<()> {
    let best = net.best_route_to(server.ip()).await?;
    let destination: IpNet = if server.is_ipv4() {
        format!("{}/32", server.ip()).parse().unwrap()
    } else {
        format!("{}/128", server.ip()).parse().unwrap()
    };

    net.replace_route(&RouteSpec {
        destination,
        gateway: best.gateway,
        interface_index: Some(best.interface_index),
        source: None,
    })
    .await
    .with_context(|| {
        format!(
            "preserving physical route to RVPN server {server} through interface index {} via {:?}",
            best.interface_index, best.gateway
        )
    })?;

    tracing::info!(
        %server,
        interface_index = best.interface_index,
        gateway = ?best.gateway,
        "preserved physical route to RVPN server using RTM_GETROUTE"
    );
    Ok(())
}

pub async fn teardown_client_network(
    dev: &VirtualInterface,
    config: &ClientConfig,
    server: SocketAddr,
    networkmanager_interfaces: &[String],
) {
    let Ok(net) = SystemNet::new() else {
        tracing::warn!("could not open rtnetlink connection during client network teardown");
        return;
    };
    let Ok(interface_index) = net.interface_index(dev.name()).await else {
        for interface in networkmanager_interfaces {
            let _ = net.deactivate_networkmanager_client_tun(interface).await;
        }
        return;
    };

    if config.routing.default_route {
        let gateway = config
            .routing
            .gateway
            .as_deref()
            .and_then(|s| s.parse().ok());
        let source = tunnel_source(config, false).ok();
        for destination in ["0.0.0.0/1", "128.0.0.0/1"] {
            if let Ok(destination) = destination.parse() {
                let _ = net
                    .delete_route(&RouteSpec {
                        destination,
                        gateway,
                        interface_index: Some(interface_index),
                        source,
                    })
                    .await;
            }
        }
        remove_server_route(&net, server, false).await;
    }

    if config.routing.default_route_v6 {
        let gateway = config
            .routing
            .gateway_v6
            .as_deref()
            .and_then(|s| s.parse().ok());
        let source = tunnel_source(config, true).ok();
        for destination in ["::/1", "8000::/1"] {
            if let Ok(destination) = destination.parse() {
                let _ = net
                    .delete_route(&RouteSpec {
                        destination,
                        gateway,
                        interface_index: Some(interface_index),
                        source,
                    })
                    .await;
            }
        }
        remove_server_route(&net, server, true).await;
    }

    if networkmanager_interfaces.is_empty()
        && config.interface.dns_servers.is_some()
        && let Err(error) = net.revert_dns(dev.name()).await
    {
        tracing::warn!(%error, "failed to revert RVPN DNS configuration");
    }

    if config.routing.default_route || config.routing.default_route_v6 {
        let uid = unsafe { libc::geteuid() };
        if let Err(error) = net.remove_kill_switch(uid).await {
            tracing::warn!(%error, "failed to remove Linux RVPN kill switch");
        }
    }

    for interface in networkmanager_interfaces {
        if let Err(error) = net.deactivate_networkmanager_client_tun(interface).await {
            tracing::warn!(%error, interface, "failed to deactivate RVPN NetworkManager profile");
        }
    }
}

async fn remove_server_route(net: &SystemNet, server: SocketAddr, ipv6: bool) {
    if server.is_ipv6() != ipv6 {
        return;
    }

    let Ok(best) = net.best_route_to(server.ip()).await else {
        return;
    };
    let destination: IpNet = if ipv6 {
        format!("{}/128", server.ip()).parse().unwrap()
    } else {
        format!("{}/32", server.ip()).parse().unwrap()
    };
    let _ = net
        .delete_route(&RouteSpec {
            destination,
            gateway: best.gateway,
            interface_index: Some(best.interface_index),
            source: None,
        })
        .await;
}

fn tunnel_source(config: &ClientConfig, ipv6: bool) -> Result<IpAddr> {
    config
        .interface
        .address
        .iter()
        .chain(&config.interface.addresses)
        .filter_map(|cidr| cidr.split('/').next())
        .find_map(|address| {
            address
                .parse::<IpAddr>()
                .ok()
                .filter(|address| address.is_ipv6() == ipv6)
        })
        .with_context(|| {
            format!(
                "default {} routing requires an address of the same family on the tunnel interface",
                if ipv6 { "IPv6" } else { "IPv4" }
            )
        })
}

pub async fn refresh_client_endpoint(
    dev: &VirtualInterface,
    config: &ClientConfig,
    old_server: SocketAddr,
    new_server: SocketAddr,
) -> Result<()> {
    let net = SystemNet::new().context("opening Linux rtnetlink connection")?;
    if old_server.ip() != new_server.ip() {
        remove_endpoint_route(&net, old_server).await;
    }
    if config.routing.default_route || config.routing.default_route_v6 {
        let uid = unsafe { libc::geteuid() };
        net.install_kill_switch(&KillSwitchSpec {
            endpoint: new_server,
            tunnel_interface: Some(dev.name().to_owned()),
            uid,
        })
        .await
        .context("refreshing Linux RVPN kill switch")?;
        preserve_server_route(&net, new_server).await?;
    }
    Ok(())
}

async fn remove_endpoint_route(net: &SystemNet, server: SocketAddr) {
    let Ok(best) = net.best_route_to(server.ip()).await else {
        return;
    };
    let destination: IpNet = if server.is_ipv4() {
        format!("{}/32", server.ip()).parse().unwrap()
    } else {
        format!("{}/128", server.ip()).parse().unwrap()
    };
    let _ = net
        .delete_route(&RouteSpec {
            destination,
            gateway: best.gateway,
            interface_index: Some(best.interface_index),
            source: None,
        })
        .await;
}
