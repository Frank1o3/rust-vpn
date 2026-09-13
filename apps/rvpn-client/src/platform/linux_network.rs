//! Network address assignment and routing configuration for the RVPN client.

use anyhow::{Context, Result, bail};
use rvpn_config::ClientConfig;
use rvpn_interface::VirtualInterface;
use std::net::SocketAddr;
use tokio::process::Command;

pub async fn configure_client_network(
    dev: &VirtualInterface,
    config: &ClientConfig,
    server: SocketAddr,
) -> Result<()> {
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

        preserve_server_route(server).await?;

        route_replace("0.0.0.0/1", Some(gateway), dev.name()).await?;
        route_replace("128.0.0.0/1", Some(gateway), dev.name()).await?;
    }

    if config.routing.default_route_v6 {
        let gateway = config
            .routing
            .gateway_v6
            .as_deref()
            .expect("validated gateway");

        preserve_server_route(server).await?;

        route_replace("::/1", Some(gateway), dev.name()).await?;
        route_replace("8000::/1", Some(gateway), dev.name()).await?;
    }
    Ok(())
}

async fn preserve_server_route(server: SocketAddr) -> Result<()> {
    let output = Command::new("ip")
        .args([
            if server.is_ipv6() { "-6" } else { "-4" },
            "route",
            "get",
            &server.ip().to_string(),
        ])
        .output()
        .await
        .context("querying existing route to RVPN server")?;

    if !output.status.success() {
        bail!(
            "ip route get failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let route = String::from_utf8_lossy(&output.stdout);
    let fields: Vec<&str> = route.split_whitespace().collect();

    let gateway = fields
        .windows(2)
        .find(|window| window[0] == "via")
        .map(|window| window[1]);

    let device = fields
        .windows(2)
        .find(|window| window[0] == "dev")
        .map(|window| window[1]);

    let Some(device) = device else {
        bail!("could not determine physical interface for RVPN server route");
    };

    let destination = if server.is_ipv6() {
        format!("{}/128", server.ip())
    } else {
        format!("{}/32", server.ip())
    };

    if let Some(gateway) = gateway {
        route_replace(&destination, Some(gateway), device).await?;
    } else {
        route_replace(&destination, None, device).await?;
    }

    tracing::info!(
        server = %server,
        gateway = gateway.unwrap_or("<direct>"),
        device,
        "preserved physical route to RVPN server"
    );

    Ok(())
}

pub async fn teardown_client_network(
    dev: &VirtualInterface,
    config: &ClientConfig,
    server: SocketAddr,
) {
    if config.routing.default_route {
        for half in ["0.0.0.0/1", "128.0.0.0/1"] {
            let _ = run("ip", ["route", "del", half, "dev", dev.name()]).await;
        }
        if server.is_ipv4() {
            let endpoint = format!("{}/32", server.ip());
            let _ = run("ip", ["route", "del", &endpoint]).await;
        }
    }
    if config.routing.default_route_v6 {
        for half in ["::/1", "8000::/1"] {
            let _ = run("ip", ["-6", "route", "del", half, "dev", dev.name()]).await;
        }
        if server.is_ipv6() {
            let endpoint = format!("{}/128", server.ip());
            let _ = run("ip", ["-6", "route", "del", &endpoint]).await;
        }
    }
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
