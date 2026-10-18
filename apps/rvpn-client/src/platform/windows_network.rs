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
    let tun = if matches!(mode, DeviceMode::Tun | DeviceMode::Both) {
        Some(
            VirtualInterface::create(TunConfig {
                name: config.interface.name.clone(),
                mtu,
                mode: DeviceMode::Tun,
            })
            .await?,
        )
    } else {
        None
    };
    if matches!(mode, DeviceMode::Tap | DeviceMode::Both) {
        anyhow::bail!("Windows Wintun currently supports TUN mode only");
    }
    Ok((tun, None, false))
}

pub async fn install_bootstrap_kill_switch(config: &ClientConfig) -> Result<bool> {
    if !config.routing.default_route && !config.routing.default_route_v6 {
        return Ok(false);
    }
    let endpoint = config
        .server
        .parse::<SocketAddr>()
        .context("Windows default-route bootstrap requires a numeric VPN endpoint")?;
    SystemNet::new()?
        .install_kill_switch(&KillSwitchSpec {
            endpoint,
            tunnel_interface: None,
            uid: 0,
        })
        .await
        .context("installing Windows bootstrap kill switch")?;
    Ok(true)
}

pub async fn remove_bootstrap_kill_switch() -> Result<()> {
    SystemNet::new()?
        .remove_kill_switch(0)
        .await
        .context("removing Windows bootstrap kill switch")
}

pub async fn configure_client_network(
    dev: &VirtualInterface,
    config: &ClientConfig,
    server: SocketAddr,
    _networkmanager_managed: bool,
) -> Result<()> {
    let net = SystemNet::new().context("opening Windows IP Helper networking backend")?;
    let interface_index = net.interface_index(dev.name()).await?;
    net.set_link_up(dev.name()).await?;

    for address in config
        .interface
        .address
        .iter()
        .chain(&config.interface.addresses)
    {
        let address: IpNet = address
            .parse()
            .with_context(|| format!("invalid configured interface address: {address}"))?;
        net.add_address(dev.name(), address).await?;
    }

    if config.routing.default_route || config.routing.default_route_v6 {
        preserve_server_route(&net, server).await?;
        net.install_kill_switch(&KillSwitchSpec {
            endpoint: server,
            tunnel_interface: Some(dev.name().to_owned()),
            uid: 0,
        })
        .await
        .context("installing Windows RVPN kill switch")?;
    }

    for route in &config.routing.routes {
        let destination: IpNet = route
            .parse()
            .with_context(|| format!("invalid configured route: {route}"))?;
        net.replace_route(&RouteSpec {
            destination,
            gateway: None,
            interface_index: Some(interface_index),
            source: None,
        })
        .await
        .with_context(|| format!("installing configured Windows route {destination}"))?;
    }

    if config.routing.default_route {
        ensure_gateway_family(config.routing.gateway.as_deref(), false)?;
        for prefix in ["0.0.0.0/1", "128.0.0.0/1"] {
            install_tunnel_route(&net, prefix, interface_index, dev.name()).await?;
        }
    }
    if config.routing.default_route_v6 {
        ensure_gateway_family(config.routing.gateway_v6.as_deref(), true)?;
        for prefix in ["::/1", "8000::/1"] {
            install_tunnel_route(&net, prefix, interface_index, dev.name()).await?;
        }
    }
    Ok(())
}

async fn install_tunnel_route(
    net: &SystemNet,
    prefix: &str,
    interface_index: u32,
    interface: &str,
) -> Result<()> {
    let destination: IpNet = prefix.parse().expect("static route prefix is valid");
    net.replace_route(&RouteSpec {
        destination,
        // Wintun is a layer-3 TUN interface; packets are written directly to the tunnel queue.
        gateway: None,
        interface_index: Some(interface_index),
        source: None,
    })
    .await
    .with_context(|| {
        format!("installing Windows tunnel route {destination} on interface {interface}")
    })
}

fn ensure_gateway_family(gateway: Option<&str>, ipv6: bool) -> Result<()> {
    let gateway: IpAddr = gateway
        .context("validated tunnel gateway is missing")?
        .parse()
        .context("invalid configured tunnel gateway")?;
    anyhow::ensure!(
        gateway.is_ipv6() == ipv6,
        "tunnel gateway address family does not match the route"
    );
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
        source: best.source,
    })
    .await
    .with_context(|| format!("preserving the physical route to RVPN endpoint {server}"))
}

pub async fn teardown_client_network(
    dev: &VirtualInterface,
    config: &ClientConfig,
    server: SocketAddr,
    _networkmanager_interfaces: &[String],
) {
    let net = match SystemNet::new() {
        Ok(net) => net,
        Err(error) => {
            tracing::warn!(%error, "could not open Windows IP Helper backend during teardown");
            return;
        }
    };
    match net.interface_index(dev.name()).await {
        Ok(interface_index) => {
            remove_configured_routes(&net, config, interface_index).await;
            if config.routing.default_route {
                remove_tunnel_routes(&net, ["0.0.0.0/1", "128.0.0.0/1"], interface_index).await;
            }
            if config.routing.default_route_v6 {
                remove_tunnel_routes(&net, ["::/1", "8000::/1"], interface_index).await;
            }
            if config.routing.default_route && server.is_ipv4()
                || config.routing.default_route_v6 && server.is_ipv6()
            {
                remove_server_route(&net, server).await;
            }
        }
        Err(error) => {
            tracing::warn!(%error, "could not find Windows RVPN interface during teardown");
        }
    }
    if (config.routing.default_route || config.routing.default_route_v6)
        && let Err(error) = net.remove_kill_switch(0).await
    {
        tracing::warn!(%error, "failed to remove Windows RVPN kill switch");
    }
}

async fn remove_configured_routes(
    net: &SystemNet,
    config: &ClientConfig,
    interface_index: u32,
) {
    for route in &config.routing.routes {
        let destination = match route.parse::<IpNet>() {
            Ok(destination) => destination,
            Err(error) => {
                tracing::warn!(%error, %route, "could not parse configured Windows route during teardown");
                continue;
            }
        };
        if let Err(error) = net
            .delete_route(&RouteSpec {
                destination,
                gateway: None,
                interface_index: Some(interface_index),
                source: None,
            })
            .await
        {
            tracing::debug!(%error, %destination, interface_index, "failed to remove configured Windows route");
        }
    }
}

async fn remove_tunnel_routes<const N: usize>(
    net: &SystemNet,
    prefixes: [&str; N],
    interface_index: u32,
) {
    for prefix in prefixes {
        if let Ok(destination) = prefix.parse() {
            if let Err(error) = net
                .delete_route(&RouteSpec {
                    destination,
                    gateway: None,
                    interface_index: Some(interface_index),
                    source: None,
                })
                .await
            {
                tracing::debug!(%error, %prefix, "failed to remove Windows tunnel route");
            }
        }
    }
}

async fn remove_server_route(net: &SystemNet, server: SocketAddr) {
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

pub async fn refresh_client_endpoint(
    dev: &VirtualInterface,
    config: &ClientConfig,
    old_server: SocketAddr,
    new_server: SocketAddr,
) -> Result<()> {
    if old_server == new_server {
        return Ok(());
    }
    let net = SystemNet::new().context("opening Windows IP Helper networking backend")?;
    if old_server.ip() != new_server.ip() {
        remove_server_route(&net, old_server).await;
    }

    if config.routing.default_route && new_server.is_ipv4()
        || config.routing.default_route_v6 && new_server.is_ipv6()
    {
        preserve_server_route(&net, new_server).await?;
        net.install_kill_switch(&KillSwitchSpec {
            endpoint: new_server,
            tunnel_interface: Some(dev.name().to_owned()),
            uid: 0,
        })
        .await
        .context("refreshing Windows RVPN kill switch")?;
    }
    Ok(())
}
