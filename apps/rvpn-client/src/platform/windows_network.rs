use anyhow::{Context, Result, bail};
use rvpn_config::ClientConfig;
use rvpn_interface::VirtualInterface;
use std::net::{IpAddr, SocketAddr};
use tokio::process::Command;

pub async fn configure_client_network(
    dev: &VirtualInterface,
    config: &ClientConfig,
    server: SocketAddr,
) -> Result<()> {
    set_interface_enabled(dev.name()).await?;

    let addresses = config
        .interface
        .address
        .iter()
        .chain(&config.interface.addresses);

    for address in addresses {
        add_interface_address(dev.name(), address).await?;
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
            .expect("validated gateway_v6");

        preserve_server_route(server).await?;

        route_replace("::/1", Some(gateway), dev.name()).await?;
        route_replace("8000::/1", Some(gateway), dev.name()).await?;
    }

    Ok(())
}

async fn set_interface_enabled(name: &str) -> Result<()> {
    let name = ps_quote(name);
    run_powershell(&format!(
        "Set-NetIPInterface -InterfaceAlias {name} -Dhcp Disabled -ErrorAction Stop | Out-Null"
    ))
    .await
}

async fn add_interface_address(name: &str, address: &str) -> Result<()> {
    let (ip, prefix) = split_cidr(address)?;
    let family = if ip.is_ipv4() { "IPv4" } else { "IPv6" };
    let name = ps_quote(name);
    let address = ps_quote(&ip.to_string());

    let script = format!(
        "if (-not (Get-NetIPAddress -InterfaceAlias {name} -IPAddress {address} -ErrorAction SilentlyContinue)) {{ New-NetIPAddress -InterfaceAlias {name} -IPAddress {address} -PrefixLength {prefix} -AddressFamily {family} -PolicyStore ActiveStore -ErrorAction Stop | Out-Null }}"
    );

    run_powershell(&script).await
}

async fn preserve_server_route(server: SocketAddr) -> Result<()> {
    let ip = ps_quote(&server.ip().to_string());
    let prefix = if server.is_ipv4() {
        ps_quote(&format!("{}/32", server.ip()))
    } else {
        ps_quote(&format!("{}/128", server.ip()))
    };
    let family = if server.is_ipv4() { "IPv4" } else { "IPv6" };

    let script = format!(
        "$route = Find-NetRoute -RemoteIPAddress {ip} -ErrorAction Stop | Sort-Object RouteMetric | Select-Object -First 1; if ($null -eq $route) {{ throw 'could not determine the physical route to the RVPN server' }}; $existing = Get-NetRoute -DestinationPrefix {prefix} -AddressFamily {family} -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue; if ($null -eq $existing) {{ New-NetRoute -DestinationPrefix {prefix} -InterfaceIndex $route.InterfaceIndex -NextHop $route.NextHop -PolicyStore ActiveStore -ErrorAction Stop | Out-Null }}; Write-Output ($route.InterfaceIndex.ToString() + '|' + $route.NextHop.ToString())"
    );

    let output = run_powershell_output(&script).await?;
    let fields: Vec<&str> = output.trim().split('|').collect();
    if fields.len() != 2 {
        bail!("unexpected Find-NetRoute output while preserving RVPN server route");
    }

    tracing::info!(
        server = %server,
        interface_index = fields[0],
        gateway = fields[1],
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
        for prefix in ["0.0.0.0/1", "128.0.0.0/1"] {
            let _ = route_delete(prefix, dev.name()).await;
        }
        if server.is_ipv4() {
            let endpoint = format!("{}/32", server.ip());
            let _ = route_delete(&endpoint, "").await;
        }
    }

    if config.routing.default_route_v6 {
        for prefix in ["::/1", "8000::/1"] {
            let _ = route_delete(prefix, dev.name()).await;
        }
        if server.is_ipv6() {
            let endpoint = format!("{}/128", server.ip());
            let _ = route_delete(&endpoint, "").await;
        }
    }
}

async fn route_replace(destination: &str, gateway: Option<&str>, device: &str) -> Result<()> {
    let (destination_ip, _) = split_cidr(destination)?;
    let family = if destination_ip.is_ipv4() {
        "IPv4"
    } else {
        "IPv6"
    };
    let destination = ps_quote(destination);
    let device = ps_quote(device);

    let next_hop = match gateway {
        Some(gateway) => gateway.to_owned(),
        None if destination_ip.is_ipv4() => "0.0.0.0".to_owned(),
        None => "::".to_owned(),
    };
    let next_hop = ps_quote(&next_hop);

    run_powershell(&format!(
        "New-NetRoute -DestinationPrefix {destination} -InterfaceAlias {device} -NextHop {next_hop} -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null"
    ))
    .await
    .with_context(|| format!("adding Windows {family} route {destination}"))
}

async fn route_delete(destination: &str, device: &str) -> Result<()> {
    let (destination_ip, _) = split_cidr(destination)?;
    let family = if destination_ip.is_ipv4() {
        "IPv4"
    } else {
        "IPv6"
    };
    let destination = ps_quote(destination);

    let interface_filter = if device.is_empty() {
        String::new()
    } else {
        format!(" | Where-Object InterfaceAlias -eq {}", ps_quote(device))
    };

    let script = format!(
        "Get-NetRoute -DestinationPrefix {destination} -AddressFamily {family} -ErrorAction SilentlyContinue{interface_filter} | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue"
    );

    run_powershell(&script).await
}

fn split_cidr(value: &str) -> Result<(IpAddr, u8)> {
    let (address, prefix) = value
        .rsplit_once('/')
        .with_context(|| format!("invalid CIDR prefix `{value}`"))?;
    let address = address
        .parse::<IpAddr>()
        .with_context(|| format!("invalid IP address `{address}`"))?;
    let prefix = prefix
        .parse::<u8>()
        .with_context(|| format!("invalid CIDR prefix length `{prefix}`"))?;

    let valid = match address {
        IpAddr::V4(_) => prefix <= 32,
        IpAddr::V6(_) => prefix <= 128,
    };
    if !valid {
        bail!("CIDR prefix length is invalid for address `{address}`");
    }

    Ok((address, prefix))
}

fn ps_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

async fn run_powershell(script: &str) -> Result<()> {
    let output = Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .output()
        .await
        .context("running PowerShell networking command")?;

    if output.status.success() {
        Ok(())
    } else {
        bail!(
            "PowerShell networking command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
}

async fn run_powershell_output(script: &str) -> Result<String> {
    let output = Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .output()
        .await
        .context("running PowerShell networking query")?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        bail!(
            "PowerShell networking query failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
}


pub async fn refresh_client_endpoint(
    _dev: &VirtualInterface,
    config: &ClientConfig,
    old_server: SocketAddr,
    new_server: SocketAddr,
) -> Result<()> {
    if old_server == new_server {
        return Ok(());
    }
    if config.routing.default_route && old_server.is_ipv4() {
        let _ = route_delete(&format!("{}/32", old_server.ip()), "").await;
    }
    if config.routing.default_route_v6 && old_server.is_ipv6() {
        let _ = route_delete(&format!("{}/128", old_server.ip()), "").await;
    }
    if config.routing.default_route && new_server.is_ipv4() {
        return preserve_server_route(new_server).await;
    }
    if config.routing.default_route_v6 && new_server.is_ipv6() {
        return preserve_server_route(new_server).await;
    }
    Ok(())
}
