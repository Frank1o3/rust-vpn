//! Network address assignment and routing configuration for the RVPN client.

use anyhow::{Context, Result, bail};
use rvpn_config::ClientConfig;
use rvpn_interface::TunDevice;
use tokio::process::Command;

/// Configures IP addresses and routes on the host for the primary VPN interface.
pub async fn configure_client_network(dev: &TunDevice, config: &ClientConfig) -> Result<()> {
    let addresses = config
        .interface
        .address
        .iter()
        .chain(&config.interface.addresses);
    if config.interface.address.is_some() || !config.interface.addresses.is_empty() {
        for address in addresses {
            run("ip", ["address", "replace", address, "dev", dev.name()]).await?;
        }
        run("ip", ["link", "set", "dev", dev.name(), "up"]).await?;
    }
    for route in &config.routing.routes {
        route_replace(route, None, dev.name()).await?;
    }
    if config.routing.default_route {
        let gateway = config
            .routing
            .gateway
            .as_deref()
            .expect("validated gateway");
        if config.server.is_ipv4() {
            let endpoint_gateway = config
                .routing
                .endpoint_gateway
                .as_deref()
                .expect("validated endpoint gateway");
            let endpoint = format!("{}/32", config.server.ip());
            route_replace(&endpoint, Some(endpoint_gateway), "").await?;
        }
        route_replace("default", Some(gateway), dev.name()).await?;
    }
    if config.routing.default_route_v6 {
        let gateway = config
            .routing
            .gateway_v6
            .as_deref()
            .expect("validated gateway");
        if config.server.is_ipv6() {
            let endpoint_gateway = config
                .routing
                .endpoint_gateway_v6
                .as_deref()
                .expect("validated endpoint gateway");
            let endpoint = format!("{}/128", config.server.ip());
            route_replace(&endpoint, Some(endpoint_gateway), "").await?;
        }
        route_replace("default", Some(gateway), dev.name()).await?;
    }
    Ok(())
}

async fn route_replace(destination: &str, gateway: Option<&str>, device: &str) -> Result<()> {
    let ipv6 = destination.contains(':') || gateway.is_some_and(|value| value.contains(':'));
    let mut args = if ipv6 {
        vec!["-6", "route", "replace", destination]
    } else {
        vec!["route", "replace", destination]
    };
    if let Some(gateway) = gateway {
        args.extend(["via", gateway]);
    }
    if !device.is_empty() {
        args.extend(["dev", device]);
    }
    run("ip", args).await
}

async fn run<'a>(program: &str, args: impl IntoIterator<Item = &'a str>) -> Result<()> {
    let output = Command::new(program)
        .args(args)
        .output()
        .await
        .context("running network command")?;
    if output.status.success() {
        Ok(())
    } else {
        bail!(
            "{} failed: {}",
            program,
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
}
