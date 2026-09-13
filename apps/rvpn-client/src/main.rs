mod handshake;
mod network;
mod tunnel;

use anyhow::{Context, Result};
use rvpn_config::{ClientConfig, DeviceMode};
use rvpn_crypto::AEAD_TAG_LEN;
use rvpn_interface::{DEFAULT_MTU, TunConfig, TunDevice};
use rvpn_protocol::HEADER_LEN;
use rvpn_transport::{TransportConfig, UdpTransport};
use std::{env, fs, net::SocketAddr};

use handshake::establish;
use network::{configure_client_network, teardown_client_network};
use tunnel::run_data_plane;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let path = env::args()
        .nth(1)
        .context("usage: rvpn-client <client.toml>")?;
    let config = ClientConfig::from_toml(&fs::read_to_string(path)?)?;

    tracing::info!(endpoint = %config.server, "resolving RVPN server endpoint");
    let server: SocketAddr = rvpn_config::resolve_endpoint(&config.server)
        .await
        .context("resolving server endpoint")?;
    config.validate_resolved(server)?;
    tracing::info!(%server, "resolved RVPN server endpoint");

    let mode = config.interface.mode();
    let mtu = config.interface.mtu.unwrap_or(DEFAULT_MTU);
    let frame_overhead = match mode {
        DeviceMode::Tun => 0,
        DeviceMode::Tap | DeviceMode::Both => 18,
    };
    let local_bind: SocketAddr = if server.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let transport = UdpTransport::open(TransportConfig {
        local_address: local_bind,
        remote_address: None,
        max_datagram_size: usize::from(mtu) + frame_overhead + HEADER_LEN + AEAD_TAG_LEN,
    })
    .await?;
    let psk = config.pre_shared_key_bytes()?;
    let obfuscation = config
        .obfuscation_key_bytes()?
        .map(rvpn_crypto::ObfuscationKey::from_bytes);
    let session = establish(
        &transport,
        server,
        psk,
        obfuscation.as_ref(),
        &config.handshake,
        None,
    )
    .await?;

    let (tun, tap) = match mode {
        DeviceMode::Tun => {
            let dev = TunDevice::create(TunConfig {
                name: config.interface.name.clone(),
                mtu,
                mode: DeviceMode::Tun,
            })
            .await?;
            (Some(dev), None)
        }
        DeviceMode::Tap => {
            let dev = TunDevice::create(TunConfig {
                name: config.interface.name.clone(),
                mtu,
                mode: DeviceMode::Tap,
            })
            .await?;
            (None, Some(dev))
        }
        DeviceMode::Both => {
            let tun_name = config.interface.name.clone();
            let tap_name = config.interface.tap_name.clone().or_else(|| {
                config
                    .interface
                    .name
                    .as_ref()
                    .map(|n| format!("{}-tap", n.chars().take(11).collect::<String>()))
            });
            let tun_dev = TunDevice::create(TunConfig {
                name: tun_name,
                mtu,
                mode: DeviceMode::Tun,
            })
            .await?;
            let tap_dev = TunDevice::create(TunConfig {
                name: tap_name,
                mtu,
                mode: DeviceMode::Tap,
            })
            .await?;
            (Some(tun_dev), Some(tap_dev))
        }
    };

    let primary_dev = tun.as_ref().or(tap.as_ref()).expect("at least one device");
    configure_client_network(primary_dev, &config, server).await?;
    tracing::info!(
        session_id = ?session.session_id(),
        %server,
        primary_interface = %primary_dev.name(),
        mode = ?mode,
        mtu = mtu,
        "authenticated RVPN client data plane started"
    );

    let shutdown = Box::pin(shutdown_signal());
    let result = run_data_plane(
        session,
        &transport,
        &config,
        server,
        psk,
        obfuscation.as_ref(),
        tun.as_ref(),
        tap.as_ref(),
        shutdown,
    )
    .await;

    tracing::info!("restoring host network state");
    teardown_client_network(primary_dev, &config, server).await;

    result
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = signal(SignalKind::terminate()).context("registering SIGTERM handler")?;
        let mut sighup = signal(SignalKind::hangup()).context("registering SIGHUP handler")?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.context("waiting for SIGINT"),
            _ = sigterm.recv() => Ok(()),
            _ = sighup.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .context("waiting for shutdown signal")
    }
}
