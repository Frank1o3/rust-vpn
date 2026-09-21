use anyhow::{Context, Result, bail};
use rvpn_config::ServerConfig;
use rvpn_interface::VirtualInterface;
use rvpn_net::{NetConfigurator, RouteSpec, SystemNet};
use tokio::process::Command;

pub async fn configure_server_interface(
    dev: &VirtualInterface,
    config: &ServerConfig,
) -> Result<()> {
    if config.interface.address.is_some() || !config.interface.addresses.is_empty() {
        let net = SystemNet::new().context("opening native networking backend")?;
        net.set_link_up(dev.name()).await?;

        for address in config
            .interface
            .address
            .iter()
            .chain(&config.interface.addresses)
        {
            let prefix = rvpn_net::cidr(address)
                .with_context(|| format!("invalid configured interface address: {address}"))?;
            net.add_address(dev.name(), prefix).await?;
        }
    }
    Ok(())
}

pub async fn run<'a>(program: &str, args: impl IntoIterator<Item = &'a str>) -> Result<()> {
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