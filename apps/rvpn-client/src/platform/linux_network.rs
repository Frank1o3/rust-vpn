use anyhow::{Context, Result};
use ipnet::IpNet;
use rvpn_config::ClientConfig;
use rvpn_interface::VirtualInterface;
use rvpn_net::{KillSwitchSpec, NetConfigurator, RouteSpec, SystemNet};
use std::net::{IpAddr, SocketAddr};

pub async fn configure_client_network(
    dev: &VirtualInterface,
    config: &ClientConfig,
    server: SocketAddr,
) -> Result<()> {
    let net = SystemNet::new().context("opening Linux rtnetlink connection")?;
    let interface_index = net.interface_index(dev.name()).await?;

    net.set_link_up(dev.name()).await?;

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
        .await?;
    }

    if config.routing.default_route || config.routing.default_route_v6 {
        let uid = unsafe { libc::geteuid() };
        net.install_kill_switch(&KillSwitchSpec {
            endpoint: server,
            tunnel_interface: dev.name().to_owned(),
            uid,
        })
        .await
        .context("installing persistent Linux kill switch")?;
        tracing::info!(
            uid,
            "Linux RVPN kill switch is active before default routes are installed"
        );
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
            .await?;
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
            .await?;
        }
    }

    if let Ok(dns_servers) = config.interface.dns_server_list()
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
    .await?;

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
) {
    let Ok(net) = SystemNet::new() else {
        tracing::warn!("could not open rtnetlink connection during client network teardown");
        return;
    };
    let Ok(interface_index) = net.interface_index(dev.name()).await else {
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

    if config.interface.dns_servers.is_some()
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
            tunnel_interface: dev.name().to_owned(),
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
